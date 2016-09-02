# Mach-O dependency tree walker

Gets list of input files from positional arguments or package listings and walks dependency tree of each architecture independently. Binaries with missing dependencies are marked.

#### Limitations
- Currently doesn't support any of the DYLD_* environment variables that affect dyld search -- there is no place for those in production environments anyway.
- Doesn't make any attempt to resolve imported symbols.

# License
This code is made available under a permissive MIT license. Please refer to the LICENSE file for details.

# Filing bugs

Please use GitHub issue tracker. Search for an existing bug or create a new one and add reproduction steps and a description of what goes wrong. Or fix it and create a pull request.

# Environment

- python 3.x
- macholib 1.7 
    - ```pip3 install macholib```
- best used on OSX

# Standard output and log format

Dependency tree is printed with a 3 flag prefix: ```[MES]``` Missing, Excluded, System. Then follows dependency name (load command) and resolved absolute path (if found).

##### Resolved system file:
```
	[  S] /usr/lib/libz.1.dylib -> /usr/lib/libz.1.dylib
```

##### Resolved rpath dependency
```
	[   ] @rpath/QtCore.framework/Versions/5/QtCore -> /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtCore.framework/Versions/5/QtCore
```

# JSON report format

Report is a slightly cleaned up dump of node cache generated while processing dependencies. Root object is a flat unordered array of nodes. Each node represents a Mach-O binary either found in one of inspected packages or at explicitly specified paths or a dependency binary. Relations between nodes can be recovered by searching for full Node based on Node.Arch.DependencyNode.

##### Root object
```javascript
[array of Nodes]
```

##### Node
```javascript
{
   	path: string // absolute resolved path to the binary (if found), partially resolved dependency name if not found
   	package: string // package name if this node was found in a package specified by --pkgs
    root: bool, optional // true if node is a root node (explicitly specified as opposed to being a dependency) 
    excluded: bool, optional // true if node matched anything in exclusion list
	exists: bool // true if binary was found on the system
	parsed: bool // true if binary was successfully parsed
	system: bool // true if system is declared to be a system binary (located in /usr/lib or /System/Library, see isSystemLib())
	satisfied: bool, optional // true if all dependencies of this node are found or excluded by one of exclusion rules
	restrictarch: string, optional // name of required architecture (when this node is a dependency of another node)
	@loader_path: string, optional // resolved value of @loader_path as dyld would see it
	@executable_path: string, optional // resolved value of @executable_path as dyld would see it (set and tracked through whole dependency tree when tree starts from an executable)
	parentRpathStack: [array of strings] // resolved RPATH stack, tracked from the start of dependency tree. See dyld manual for more info, TL;DR -- expanded rpaths are cascading down dependency chain
	arch: { "architecture name": Arch }
	missing: [array of DependencyNodes] // list of missing dependencies
}
```

##### Arch
```javascript
{
	name: string // architecture name, "x86_64", etc
	rpaths: [array of strings] // list of resolved rpaths found in this binary
	dependencies: [array of DependencyNodes]
}
```

##### DependencyNode
```javascript
{
    name: string // name of the dependency as recorded in load Mach-O commands
    path: string, optional // full resolved path if found on system
    excluded: bool
    system: bool
    restrictArch: string
    parentRpathStack: [array of strings] 
    @executable_path: string, optional
}
```

# Exclusions file format
- Empty lines and lines starting with '#' are ignored.
- Each line is a separate regexp that must match full "exclusion ID" of a dependency, where ID is built using full ancestry and absolute dependency path (or name, as given by load command, when path is not resolved), separated by ' : ' (space-colon-space). 
For example:
```
# Ignore missing dependencies that start with '@rpath' on all embedded frameworks for all apps in /Application folder.
# Because they might rely on rpath being set in parent executable.
# At the same time do not ignore those dependencies when frameworks are loaded by something else.
# That needs correct rpath set to work and is usually a legitimate error.
/Applications/.*\.app/Contents/Frameworks/[^:]*\.framework/.* : @rpath/.*
```
- Exclusion IDs and regexp patterns that match them are printed with verbosity 100+.

# Usage

```./collect_macho_report.py [--exclusions <PATH>] [--ignoresystem] [--teamcity] [--verbosity <INT>] [--log <PATH>] [--report <PATH>] <[--pkgs <REGEXP>] ... | [PATH] ...>```

- ```--exclusions <PATH>```
	Path to exclusions file -- dependencies matching anything inside will be automatically marked as resolved and will not affect status of the parent.
- ```--teamcity```
	Autodetected when run by TeamCity®, formats standard output messages as ```##teamcity[message ...]``` for TeamCity build log integration.
- ```--verbosity <INT>```
	Default value: 1.
	- 0 -- output nothing but missing dependencies.
	- 1~6 -- general information about processed binaries, increasingly more verbose.
	- 101+ -- debug output.
- ```--ignoresystem```
	Stops tree traversal at binaries installed in /System/Library and /usr/lib, eliminates ~60k nodes. Highly recommended.
- ```--pkgs <REGEXP>```
	Get input file list from installed packages matching REGEXP. See ```/usr/sbin/pkgutil --help``` for more info. Can be specified multiple times.
- ```--log <PATH>```
	Path to log file. Log follows stdout format, but ignores teamcity and is always at full verbosity.
- ```--report <PATH>```
	Path to json dump of processed nodes.
- ```[PATH ...]```
	One or more file or directory paths. All Mach-O binaries found will be added to input file list to be processed. Can be used together with ```--pkgs``` option.

# Examples

### Installation check
Check dyld dependencies for all Mach-O binaries installed by SMART Technologies, using exclusion file with known irrelevancies and writing both log and JSON dump (for processing elsewhere).
```
python3 collect_macho_report.py --verbosity 0 --pkgs "com.smarttech.*" --ignoresystem --exclusions "esi_exclusions_osx.txt" --log "log.txt" --report "report.json"
```
With verbosity 0 anything on stdout basically means there are missing dependencies and installation is broken.

### Single app check
Check dyld dependencies for all Mach-O binaries found under specified application bundle.
```
python3 collect_macho_report.py /Applications/SMART\ Technologies/SMART\ Tools/SMART\ Product\ Update.app --verbosity 3 --ignoresystem
```
Output:
```
/Applications/SMART Technologies/SMART Tools/SMART Product Update.app/Contents/MacOS/SMART Product Update
	package:
	exists
	valid Mach-O
	loader_path: /Applications/SMART Technologies/SMART Tools/SMART Product Update.app/Contents/MacOS
	executable_path: /Applications/SMART Technologies/SMART Tools/SMART Product Update.app/Contents/MacOS
	arch: x86_64
		rpaths:
			/Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1
		dependencies:
			[   ] /Library/Application Support/SMART Technologies/Frameworks/crashreporterclient.framework/Versions/1.1/crashreporterclient -> /Library/Application Support/SMART Technologies/Frameworks/crashreporterclient.framework/Versions/1.1/crashreporterclient
			[  S] /usr/lib/libz.1.dylib -> /usr/lib/libz.1.dylib
			[   ] @rpath/QtWidgets.framework/Versions/5/QtWidgets -> /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtWidgets.framework/Versions/5/QtWidgets
			[   ] /Library/Application Support/SMART Technologies/Frameworks/boost.framework/Versions/1.53.0/boost -> /Library/Application Support/SMART Technologies/Frameworks/boost.framework/Versions/1.53.0/boost
			[   ] /Library/Application Support/SMART Technologies/Frameworks/activation.framework/Versions/A-cl42/activation -> /Library/Application Support/SMART Technologies/Frameworks/activation.framework/Versions/A-cl42/activation
			[  S] /System/Library/Frameworks/Carbon.framework/Versions/A/Carbon -> /System/Library/Frameworks/Carbon.framework/Versions/A/Carbon
			[  S] /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit -> /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit
			[  S] /System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices -> /System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices
			[  S] /System/Library/Frameworks/Security.framework/Versions/A/Security -> /System/Library/Frameworks/Security.framework/Versions/A/Security
			[  S] /System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration -> /System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration
			[  S] /System/Library/Frameworks/IOKit.framework/Versions/A/IOKit -> /System/Library/Frameworks/IOKit.framework/Versions/A/IOKit
			[   ] /Library/Application Support/SMART Technologies/Frameworks/preference.framework/Versions/A-cl42/preference -> /Library/Application Support/SMART Technologies/Frameworks/preference.framework/Versions/A-cl42/preference
			[   ] @rpath/QtCore.framework/Versions/5/QtCore -> /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtCore.framework/Versions/5/QtCore
			[   ] @rpath/QtGui.framework/Versions/5/QtGui -> /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtGui.framework/Versions/5/QtGui
			[   ] @rpath/QtNetwork.framework/Versions/5/QtNetwork -> /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtNetwork.framework/Versions/5/QtNetwork
			[   ] @rpath/QtXml.framework/Versions/5/QtXml -> /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtXml.framework/Versions/5/QtXml
			[   ] /Library/Application Support/SMART Technologies/Frameworks/log4cxx.framework/Versions/0.10.0-cl42/log4cxx -> /Library/Application Support/SMART Technologies/Frameworks/log4cxx.framework/Versions/0.10.0-cl42/log4cxx
			[  S] /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation -> /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation
			[  S] /usr/lib/libobjc.A.dylib -> /usr/lib/libobjc.A.dylib
			[  S] /usr/lib/libc++.1.dylib -> /usr/lib/libc++.1.dylib
			[  S] /usr/lib/libSystem.B.dylib -> /usr/lib/libSystem.B.dylib
			[  S] /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation -> /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
			[  S] /System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices -> /System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices
	dependencies satisfied
```

### Single app check with missing dependencies
```
python3 collect_macho_report.py /Applications/SMART\ Technologies/SMART\ Tools/SMART\ Product\ Update.app --verbosity 3 --ignoresystem
```
Output:

```
/Applications/SMART Technologies/SMART Tools/SMART Product Update.app/Contents/MacOS/SMART Product Update
	package:
	exists
	valid Mach-O
	loader_path: /Applications/SMART Technologies/SMART Tools/SMART Product Update.app/Contents/MacOS
	executable_path: /Applications/SMART Technologies/SMART Tools/SMART Product Update.app/Contents/MacOS
	arch: x86_64
		rpaths:
			/Users/swbuild/buildAgent/work/8868ac370fd41027/build/../artifacts/smartlib
		dependencies:
			[   ] /Library/Application Support/SMART Technologies/Frameworks/preference.framework/Versions/B/preference -> /Library/Application Support/SMART Technologies/Frameworks/preference.framework/Versions/B/preference
			[   ] /Library/Application Support/SMART Technologies/Frameworks/crashreporterclient.framework/Versions/1.3/crashreporterclient -> /Library/Application Support/SMART Technologies/Frameworks/crashreporterclient.framework/Versions/1.3/crashreporterclient
			[   ] /Library/Application Support/SMART Technologies/Frameworks/boost.framework/Versions/1.53.0/boost -> /Library/Application Support/SMART Technologies/Frameworks/boost.framework/Versions/1.53.0/boost
			[   ] /Library/Application Support/SMART Technologies/Frameworks/localization.framework/Versions/2.0.3.0/localization -> /Library/Application Support/SMART Technologies/Frameworks/localization.framework/Versions/2.0.3.0/localization
			[   ] /Library/Application Support/SMART Technologies/Frameworks/activation.framework/Versions/B/activation -> /Library/Application Support/SMART Technologies/Frameworks/activation.framework/Versions/B/activation
			[   ] /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtWidgets.framework/Versions/5/QtWidgets -> /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtWidgets.framework/Versions/5/QtWidgets
			[   ] /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtCore.framework/Versions/5/QtCore -> /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtCore.framework/Versions/5/QtCore
			[   ] /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtGui.framework/Versions/5/QtGui -> /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtGui.framework/Versions/5/QtGui
			[   ] /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtNetwork.framework/Versions/5/QtNetwork -> /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtNetwork.framework/Versions/5/QtNetwork
			[   ] /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtXml.framework/Versions/5/QtXml -> /Library/Application Support/SMART Technologies/Frameworks/Qt5.4.1/QtXml.framework/Versions/5/QtXml
			[   ] /Library/Application Support/SMART Technologies/Frameworks/log4cxx.framework/Versions/0.10.0-cl42/log4cxx -> /Library/Application Support/SMART Technologies/Frameworks/log4cxx.framework/Versions/0.10.0-cl42/log4cxx
			[  S] /System/Library/Frameworks/Carbon.framework/Versions/A/Carbon -> /System/Library/Frameworks/Carbon.framework/Versions/A/Carbon
			[  S] /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit -> /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit
			[  S] /System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices -> /System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices
			[  S] /System/Library/Frameworks/Security.framework/Versions/A/Security -> /System/Library/Frameworks/Security.framework/Versions/A/Security
			[  S] /System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration -> /System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration
			[  S] /System/Library/Frameworks/IOKit.framework/Versions/A/IOKit -> /System/Library/Frameworks/IOKit.framework/Versions/A/IOKit
			[  S] /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation -> /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation
			[  S] /usr/lib/libobjc.A.dylib -> /usr/lib/libobjc.A.dylib
			[  S] /usr/lib/libc++.1.dylib -> /usr/lib/libc++.1.dylib
			[  S] /usr/lib/libSystem.B.dylib -> /usr/lib/libSystem.B.dylib
			[  S] /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation -> /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
			[  S] /System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices -> /System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices
	dependencies missing:
		[   ] /Library/Application Support/SMART Technologies/Frameworks/activation.framework/Versions/B/activation
				[M  ] /Library/Application Support/SMART Technologies/Frameworks/filestore.framework/Versions/B/filestore
```
Here filestore.framework is missing on the system and activation.framework depends on it. Full tree path to the missing leaf is printed in such case to help narrow down source of breakage.

# Notes
TeamCity® is a registered trade mark of JetBrains s.r.o. https://www.jetbrains.com/teamcity/