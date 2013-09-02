What's pype32? <img src="http://goo.gl/jrf7j8" align="right" height="150" style="max-width: 70px">
======

Yet another Python library to read and write [PE/PE+](http://es.wikipedia.org/wiki/Portable_Executable) files.

Usage
======

```python
>>> import pype32
>>> pe = pype32.PE(r"C:\Windows\notepad.exe")
>>> p.sectionHeaders
[<pype32.SectionHeader object at 0x01A802F0>, <pype32.SectionHeader object at 0x01A805F0>, <pype32.SectionHeader object at 0x01A803B0>, <pype32.SectionHeader object at 0x01A80730>]
>>> len(p.sectionHeaders)
4
>>> len(p.sections)
4
>>> p.addSection("\x90\x90\x90", name="newsec")
>>> len(p.sectionHeaders)
5
>>> len(p.sections)
5
>>> p.sectionHeaders[4].name.value
'newsec'
>>> p.sections[4]
'\x90\x90\x90\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc
```

License
======

**pype32** is distributed under the [BSD 3-Clause](http://opensource.org/licenses/BSD-3-Clause) License.

Documentation
======

You can find the **Programming Reference** documentation generated with [epydoc](http://epydoc.sourceforge.net/) for **pype32** under the [doc](doc/index.html) folder.