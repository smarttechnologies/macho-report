#!/usr/bin/env python3

import json
import os
import sys
import argparse
import queue
import collections
import functools
import concurrent.futures
import itertools
import threading
import subprocess
import plistlib
import re
from enum import Enum

from macholib import MachO
from macholib import mach_o
from macholib import util

# ==========================================================================================================

Line = collections.namedtuple('Line', ['severity', 'verbosity', 'indent', 'line'])


class LogLevel(Enum):
	INFO = 0
	WARNING = 1
	ERROR = 2


# ==========================================================================================================
def _ignored(path: str) -> bool:
	if not os.path.exists(path) or path.endswith(".dSYM"):
		return True
	return False


def _listFiles(path: str) -> set:
	files = set()
	if not _ignored(path):
		if os.path.isdir(path):
			for entry in os.listdir(path):
				files.update(_listFiles(os.path.join(path, entry)))
		else:
			files.add(os.path.abspath(path))
	return files


def _listAllFiles(paths: list) -> set:
	files = set()
	for entry in paths:
		files.update(_listFiles(entry))
	return files


# ==========================================================================================================
def _makePrefix(node: dict) -> str:
	prefixFormat = "[{0}{1}{2}] "

	missingFlag = " " if "path" in node else "M"
	excludedFlag = "E" if "excluded" in node and node["excluded"] else " "
	systemFlag = "S" if "system" in node and node["system"] else " "

	prefix = prefixFormat.format(missingFlag, excludedFlag, systemFlag)

	return prefix


def _missingTreeRecord(node: dict, indent: int, verbosity: int) -> list:
	paragraph = []

	for dependency in node["missing"]:
		prefix = _makePrefix(dependency)

		if "path" in dependency:
			paragraph.append(Line(LogLevel.INFO, verbosity+0, indent, "{}{}".format(prefix, dependency["name"])))
			paragraph.extend(_missingTreeRecord(dependency, indent+2, verbosity))
		else:
			severity = LogLevel.WARNING
			if "excluded" in dependency and dependency["excluded"]:
				severity = LogLevel.INFO
			paragraph.append(Line(severity, verbosity+0, indent, "{}{}".format(prefix, dependency["name"])))
			if "pattern" in dependency and dependency["pattern"] is not None:
				paragraph.append(Line(severity, verbosity+100, indent+1, "matched: {}".format(dependency["pattern"])))
			if "exclusionId" in dependency:
				paragraph.append(
					Line(LogLevel.INFO, verbosity+100, indent+1, "exclusionId: {}".format(dependency["exclusionId"])))

	return paragraph


def _nodeToRecord(node: dict, verbosity: int, indent: int) -> list:
	paragraph = []

	if "satisfied" in node and not node["satisfied"]:
		verbosity -= 1

	paragraph.append(Line(LogLevel.INFO, verbosity+0, indent, node["path"]))

	if "package" in node:
		paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+1, "package: {}".format(node["package"])))

	if node["exists"]:
		paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+1, "exists"))
	else:
		paragraph.append(Line(LogLevel.WARNING, verbosity+1, indent+1, "not found"))

	if "excluded" in node and node["excluded"]:
		paragraph.append(Line(LogLevel.INFO, verbosity+1, indent+1, "excluded"))
		if node["pattern"] is not None:
			paragraph.append(Line(LogLevel.INFO, verbosity+100, indent+2, "matched: {}".format(node["pattern"])))
	if "exclusionId" in node:
		paragraph.append(Line(LogLevel.INFO, verbosity+100, indent+1, "exclusionId: {}".format(node["exclusionId"])))

	if node["parsed"]:
		paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+1, "valid Mach-O"))

		if "@loader_path" in node:
			paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+1, "loader_path: {}".format(node["@loader_path"])))
		if "@executable_path" in node:
			paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+1, "executable_path: {}".format(node["@executable_path"])))

		if "parentRpathStack" in node:
			paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+1, "current rpath stack:"))
			for path in node["parentRpathStack"]:
				paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+2, path))

		for arch in node["arch"]:
			paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+1, "arch: {}".format(arch)))

			paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+2, "rpaths:"))
			for rpath in node["arch"][arch]["rpaths"]:
				paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+3, rpath))

			paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+2, "dependencies:"))
			for dependency in node["arch"][arch]["dependencies"]:
				prefix = _makePrefix(dependency)
				if "path" not in dependency:
					severity = LogLevel.WARNING
					if "excluded" in dependency and dependency["excluded"]:
						severity = LogLevel.INFO
					paragraph.append(Line(severity, verbosity+2, indent+3, "{}{} -> not found".format(prefix, dependency["name"])))
					if "pattern" in dependency and dependency["pattern"] is not None:
						paragraph.append(Line(severity, verbosity+100, indent+4, "matched: {}".format(dependency["pattern"])))
				else:
					paragraph.append(Line(LogLevel.INFO, verbosity+2, indent+3, "{} -> {}".format(prefix+dependency["name"], dependency["path"])))
				if "exclusionId" in dependency:
					paragraph.append(Line(LogLevel.INFO, verbosity+100, indent+4, "exclusionId: {}".format(dependency["exclusionId"])))
	else:
		paragraph.append(Line(LogLevel.ERROR, verbosity+0, indent+1, "failed to parse"))

	if "satisfied" in node:
		if node["satisfied"]:
			paragraph.append(Line(LogLevel.INFO, verbosity+1, indent+1, "dependencies satisfied"))
			paragraph.extend(_missingTreeRecord(node, indent+2, verbosity+1))
		else:
			paragraph.append(Line(LogLevel.WARNING, verbosity+0, indent+1, "dependencies missing:"))
			paragraph.extend(_missingTreeRecord(node, indent+2, verbosity+0))

	return paragraph


def _isSystemLib(path: str) -> bool:
	if path.startswith("/usr/lib"):
		return True
	if path.startswith("/System/Library"):
		return True
	return False


def _resolvePath(parentNode: dict, dependencyPath: str) -> (bool, str):
	path = dependencyPath

	if "@loader_path" in dependencyPath:
		path = dependencyPath.replace("@loader_path", parentNode["@loader_path"])

	if "@executable_path" in path and "@executable_path" in parentNode:
		path = path.replace("@executable_path", parentNode["@executable_path"])

	return os.path.exists(path), os.path.abspath(path)


def _makeCacheKey(node: dict) -> str:
	key = node["path"]
	if "restrictarch" in node:
		key += "@" + node["restrictarch"]
	if "@executable_path" in node:
		key += "@" + node["@executable_path"]
	if "parentRpathStack" in node:
		key += "@" + json.dumps(node["parentRpathStack"], sort_keys=True)
	return key


def _processNode(nodes: queue.Queue, node: dict, ignoreSystem: bool) -> list:
	paragraph = []
	path = node["path"]

	node["exists"] = os.path.exists(path)
	if node["exists"]:
		try:
			macho = MachO.MachO(path)
		except:
			macho = None
	
	node["parsed"] = macho is not None
	
	if node["parsed"]:
		node["@loader_path"] = os.path.dirname(path)
		node["arch"] = {}
		
		for header in macho.headers:
			archName = mach_o.CPU_TYPE_NAMES.get(header.header.cputype, header.header.cputype)
			
			if "restrictarch" in node and archName != node["restrictarch"]:
				continue
			
			node["arch"][archName] = {}
			node["arch"][archName]["name"] = archName
			node["arch"][archName]["rpaths"] = []
			node["arch"][archName]["dependencies"] = []
			
			if header.header.filetype == mach_o.MH_EXECUTE:
				node["@executable_path"] = node["@loader_path"]
			
			for command in header.commands:
				if command[0].cmd == mach_o.LC_RPATH:
					node["arch"][archName]["rpaths"].append(
						command[2][0:command[2].find(b'\x00', 0)].decode(sys.getfilesystemencoding()))
			
			# @rpath/
			# Dyld  maintains  a current stack of paths called the run path list.  When @rpath is encountered it is substituted with each path in the run path list until a loadable dylib if found.  The run path stack is built from the LC_RPATH
			# load commands in the dependency chain that lead to the current dylib load.  You can add an LC_RPATH load command to an image with the -rpath option to ld(1).  You can even add  a  LC_RPATH  load  command  path  that  starts  with
			# @loader_path/,  and  it  will push a path on the run path stack that relative to the image containing the LC_RPATH.  The use of @rpath is most useful when you have a complex directory structure of programs and dylibs which can be
			# installed anywhere, but keep their relative positions.  This scenario could be implemented using @loader_path, but every client of a dylib could need a different load path because its relative position in the file system is  dif-
			# ferent.  The use of @rpath introduces a level of indirection that simplfies things.  You pick a location in your directory structure as an anchor point.  Each dylib then gets an install path that starts with @rpath and is the path
			# to the dylib relative to the anchor point. Each main executable is linked with -rpath @loader_path/zzz, where zzz is the path from the executable to the anchor point.  At runtime dyld sets it run path to be the anchor point, then
			# each dylib is found relative to the anchor point.
			# TL;DR -- expanded rpaths are cascading down dependency chain
			rpathStack = []
			if "parentRpathStack" in node:
				rpathStack = list(node["parentRpathStack"])
			for rpath in node["arch"][archName]["rpaths"]:
				exists, resolvedPath = _resolvePath(node, rpath)
				if resolvedPath not in rpathStack:
					rpathStack.append(resolvedPath)
			
			for index, name, fileName in header.walkRelocatables():
				node["arch"][archName]["dependencies"].append({"name": fileName})
				
				exists = False

				newNodePath = None
				if "@rpath" in fileName:
					for rpath in rpathStack:
						exists, fullPath = _resolvePath(node, fileName.replace("@rpath", rpath))
						if exists:
							newNodePath = fullPath
							break
				else:
					exists, newNodePath = _resolvePath(node, fileName)
				
				if exists:
					newNode = {
						"path": newNodePath
						, "parentRpathStack": rpathStack
						, "restrictarch": archName
						, "system": _isSystemLib(newNodePath)
					}

					if "@executable_path" in node:
						newNode["@executable_path"] = node["@executable_path"]

					node["arch"][archName]["dependencies"][-1].update(newNode)
					
					if not ignoreSystem or not newNode["system"]:
						nodes.put(newNode)
	else:
		paragraph.append(Line(LogLevel.WARNING, 4, 1, "not Mach-O"))
		
	return paragraph


def _worker(nodes: queue.Queue, cache: dict, lock: threading.Lock, records: list, ignoreSystem: bool, verbosity: int):
	try:
		while True:
			paragraph = []

			try:
				node = nodes.get(True, 1)
			except:
				if verbosity > 5:
					sys.stdout.write("x")
					sys.stdout.flush()
				return

			try:
				nodeKey = _makeCacheKey(node)

				with lock:
					if nodeKey in cache:
						paragraph.append(Line(LogLevel.INFO, 5, 0, "skipping: " + nodeKey))
						process = False  # other worker is handling this node
					else:
						if verbosity > 1:
							sys.stdout.write("\routstanding queue: {} ".format(nodes.qsize()))
							sys.stdout.flush()
						paragraph.append(Line(LogLevel.INFO, 4, 0, "processing: " + nodeKey))
						cache[nodeKey] = node  # this worker will handle the node and insert updated node into cache later
						process = True

				if process:
					paragraph.extend(_processNode(nodes, node, ignoreSystem))
					with lock:
						cache[nodeKey] = node

					if node["parsed"]:
						records.append(paragraph)
						records.append(_nodeToRecord(node, verbosity=4, indent=1))
			finally:
				nodes.task_done()

	except:
		if verbosity > 5:
			sys.stdout.write("!")
			sys.stdout.flush()
		raise


# Starts a number of worker threads and fills work queue with root nodes.
# Each worker then takes one node out of queue, parses its dependencies (if not in cache already) and adds each of them as individual node back into queue.
# Workers quit when queue is empty.
# Cache key is generated based on the node path, parent architecture, current executable_path (propagated down from root executable) and parent rpath stack so far (accumulated rpaths from the whole chain starting from root binary).
# Same binary might be resolved differently based on what tries to load it and for which architecture.
# After queue is processed cache contains processed root nodes and all dependency nodes encountered.
def _gatherNodes(threadPool: concurrent.futures.Executor, targets: list, records: list, ignoreSystem: bool, verbosity: int) -> dict:
	nodes = queue.Queue()
	nodeCache = {}  # "path@arch" : node
	cacheLock = threading.Lock()

	__worker = functools.partial(_worker, nodes=nodes, cache=nodeCache, lock=cacheLock, records=records, ignoreSystem=ignoreSystem, verbosity=verbosity)

	for target in targets:
		rootFiles = _listAllFiles(target["files"])
		for path in rootFiles:
			if util.is_platform_file(path):  # ignoring all non-macho files
				nodes.put({"path": path, "root": True, "package": target["package"]})

	futures = []
	for i in range(threadPool._max_workers):
		futures.append(threadPool.submit(__worker))

	nodes.join()

	[future.result() for future in futures]  # raising exceptions if any

	return nodeCache


# Marks node as excluded if its full path (including ancestry) fully matches one of regexps in exclusion list.
def _isExcluded(node: dict, exclusions: list, ancestry: list) -> (bool, str, str):
	if "path" in node:
		fullName = node["path"]
	else:
		fullName = node["name"]

	if len(ancestry) > 0:
		fullName = " : ".join(ancestry) + " : " + fullName
	for entry in exclusions:
		if entry.fullmatch(fullName) is not None:
			return True, str(entry), fullName
	return False, None, fullName


# Runs though a node and recursively through its whole dependency tree, propagating any missing dependencies back to root.
def _checkNode(node: dict, nodes: dict, exclusions: list, ancestry: list) -> (bool, bool):
	if "satisfied" in node:
		return node["satisfied"], node["missing"]

	ancestry = list(ancestry)
	node["excluded"], node["pattern"], node["exclusionId"] = _isExcluded(node, exclusions, ancestry)
	ancestry.append(node["path"])

	if "parsed" not in node or not node["parsed"]:
		node["satisfied"] = node["excluded"]
		node["missing"] = []
		return node["satisfied"], node["missing"]

	node["satisfied"] = True
	node["missing"] = []

	for arch in node["arch"].values():
		for dependency in arch["dependencies"]:
			dependency["excluded"], dependency["pattern"], dependency["exclusionId"] = _isExcluded(dependency, exclusions, ancestry)
			if "path" not in dependency:
				node["missing"].append(dependency)
				if not dependency["excluded"]:
					node["satisfied"] = False
			elif dependency["system"]:
				pass
			else:
				key = _makeCacheKey(dependency)
				satisfied, missing = _checkNode(nodes[key], nodes, exclusions, ancestry)
				if not satisfied:
					node["satisfied"] = False
					node["missing"].append(dependency)
					node["missing"][-1]["missing"] = missing

	if node["excluded"]:
		node["satisfied"] = True

	return node["satisfied"], node["missing"]


def _updateMissing(nodes: dict, records: list, exclusions: list):
	for node in nodes.values():
		if "root" not in node or not node["root"]:
			continue

		_checkNode(node, nodes, exclusions, [])

		records.append(_nodeToRecord(node, verbosity=1, indent=0))


def _collectDependencies(threadPool: concurrent.futures.Executor, targets: list, exclusions: list, records: list, ignoreSystem: bool, verbosity: int) -> dict:
	nodes = _gatherNodes(threadPool, targets, records, ignoreSystem, verbosity)
	_updateMissing(nodes, records, exclusions)
	return nodes


# ==========================================================================================================
def _getFileList(package: str, records: list) -> dict:
	files = []
	paragraph = []

	with subprocess.Popen(["/usr/sbin/pkgutil", "--pkg-info-plist", package], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True) as process:
		out, err = process.communicate()
		root = plistlib.loads(out.encode("utf-8"), fmt=plistlib.FMT_XML)
		volume = root["volume"]

	with subprocess.Popen(["/usr/sbin/pkgutil", "--files", package, '--only-files'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True) as process:
		out, err = process.communicate()
		if process.returncode == 0:
			files = [os.path.join(volume, file) for file in out.splitlines()]

			paragraph.append(Line(LogLevel.INFO, 2, 0, "files for {}".format(package)))
			paragraph.extend([Line(LogLevel.INFO, 2, 1, file) for file in files])
		else:
			paragraph.append(Line(LogLevel.ERROR, 0, 0, "error listing files for {}\n{}".format(package, err)))

	records.append(paragraph)
	return {"package": package, "files": files}


# Lists packages matching '--pkgs' regexp and adds all files they install into target list
def _collectPackagesFileList(threadPool: concurrent.futures.Executor, pkgs: list, records: list) -> list:
	packages = []
	paragraph = []
	for entry in pkgs:
		with subprocess.Popen(["/usr/sbin/pkgutil", "--pkgs={}".format(entry)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True) as process:
			out, err = process.communicate()

			if process.returncode == 0:
				packages.extend(out.splitlines())
			else:
				paragraph.append(Line(LogLevel.ERROR, 0, 0, "error listing packages: {}\n{}".format(entry, err)))

	paragraph.append(Line(LogLevel.INFO, 1, 0, "parsing packages:"))
	records.append(paragraph)
	records.append([Line(LogLevel.INFO, 1, 1, package) for package in packages])

	futures = []
	for package in packages:
		futures.append(threadPool.submit(_getFileList, package, records))

	files = []
	for future in futures:
		files.append(future.result())

	return files


# ==========================================================================================================
def _format(teamcity: bool, record: Line) -> str:
	status = ""
	if record.severity == LogLevel.INFO:
		status = "NORMAL"
	if record.severity == LogLevel.WARNING:
		status = "WARNING"
	if record.severity == LogLevel.ERROR:
		status = "ERROR"

	if teamcity:
		if record.severity == LogLevel.ERROR:
			return "##teamcity[message text='{}' status='{}' errorDetails='{}']".format("error", status, "\t" * record.indent + record.line)
		else:
			return "##teamcity[message text='{}' status='{}']".format("\t" * record.indent + record.line, status)
	else:
		return "{}{}".format("\t" * record.indent, record.line)


def _printRecord(records: list, teamcity: bool, verbosity: int, file):
	output = "\n".join([_format(teamcity, record) for record in records if record.verbosity <= verbosity])
	if len(output) > 0:
		print(output, file=file)


# ==========================================================================================================
def _makeReport(nodes: dict) -> list:
	root = list(nodes.values())
	for entry in root:
		if "exclusionId" in entry:
			entry.pop("exclusionId")
		if "pattern" in entry:
			entry.pop("pattern")
		for arch in entry["arch"].values():
			for dependency in arch["dependencies"]:
				if "exclusionId" in dependency:
					dependency.pop("exclusionId")
				if "pattern" in dependency:
					dependency.pop("pattern")
	return root


# ==========================================================================================================
def collect(packages: list, files: list, exclusionsFile: str, logFile: str, teamcity: bool, verbosity: int, ignoreSystem: bool) -> list:
	exclusions = []
	records = []
	nodes = None
	report = None

	try:
		if exclusionsFile is not None:
			with open(exclusionsFile, "rU") as file:
				entries = [entry.strip() for entry in set(file.read().split("\n")) if not entry.startswith("#")]
				exclusions = [re.compile(entry) for entry in entries if not len(entry) == 0]
			paragraph = [Line(LogLevel.INFO, 2, 0, "exclusions:")]
			paragraph.extend([Line(LogLevel.INFO, 2, 1, str(entry)) for entry in exclusions])
			records.append([paragraph])
			_printRecord(itertools.chain.from_iterable(records[-1]), teamcity, verbosity, sys.stdout)

		targets = []
		with concurrent.futures.ThreadPoolExecutor(max_workers=200) as threadPool:
			if files is not None:
				targets = [{"package": "", "files": files}]
			if packages is not None:
				records.append(collections.deque())
				targets.extend(_collectPackagesFileList(threadPool, packages, records[-1]))
				_printRecord(itertools.chain.from_iterable(records[-1]), teamcity, verbosity, sys.stdout)

			records.append(collections.deque())
			nodes = _collectDependencies(threadPool, targets, exclusions, records[-1], ignoreSystem, verbosity)
	finally:
		if verbosity > 1:
			sys.stdout.write('\n')
		_printRecord(itertools.chain.from_iterable(records[-1]), teamcity, verbosity, sys.stdout)

		if logFile is not None:
			with open(logFile, 'w') as file:
				for entry in records:
					_printRecord(itertools.chain.from_iterable(entry), False, verbosity+99, file)
		if nodes is not None:
			report = _makeReport(nodes)

	return report


def main(argv):
	parser = argparse.ArgumentParser()
	parser.add_argument('--exclusions', default=None)
	parser.add_argument('--teamcity', action='store_true', default='TEAMCITY_BUILD_PROPERTIES_FILE' in os.environ)
	parser.add_argument('--verbosity', type=int, default=1)
	parser.add_argument('--ignoresystem', action="store_true", default=False)
	parser.add_argument('--pkgs', nargs='*', default=None)
	parser.add_argument('positional', nargs='*', default=None)
	parser.add_argument('--log', default=None)
	parser.add_argument('--report', default=None)

	args = parser.parse_args()

	report = collect(args.pkgs, args.positional, args.exclusions, args.log, args.teamcity, args.verbosity, args.ignoresystem)

	if report is not None and args.report is not None:
		with open(args.report, 'w') as file:
			json.dump(report, file)


# ==================================================================================
if __name__ == "__main__":
	main(sys.argv[1:])
