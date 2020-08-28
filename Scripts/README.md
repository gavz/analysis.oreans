#  🔎 Analysis of Oreans - Scripts 

#### Scripts used for identitifications, computation processing, cleaning, optimizing, deobfuscating, and overviewing Oreans 

## Disclaimer

Scripts provided may be changed or delayed in publishing. Scripts are primarily focused on multiple targeted x32 applications. Future support of x64 applications may or may not be provided at a later date.


## Author

* ["quosego"][ref-SELF] 


## Scripts

* [x64dbg](https://x64dbg.com/)
  * [OEP Finder (Universal Approach)](https://github.com/quosego/analysis.oreans/blob/master/Scripts/x64dbg/oreans_oep_finder_uni.py)
    * About
      * Used to find the original OEP address not used by Oreans but the original application. Knowing the OEP can help realign dumps and properly help identify the real IAT. 
    * Compatibility
      * Themida Versions 2.x to 3.x
      * WinLicense Versions 2.x to 3.x
      * CodeVirtualizer Versions 2.x to 3.x
  * TBA
 
* [IDA (7.0)](https://www.hex-rays.com/products/ida/support/download/)
  * [Macro Entry Identifier (Biased Approach)](https://github.com/quosego/analysis.oreans/blob/master/Scripts/ida/oreans_macro_entry_identifier_biased.py)
    * About
      * Used to find possible macro entries created by Oreans. Knowing the locations can help give an overview of how much protection is used, where to focus, where to remove unnessasary "buffers" and help in restoring the original code. The biased approach is not an accurate and reliable method and was commonly used in ollydbg scripts and plugins released pre 2011~ish by various reversers, like LCF-AT and Deathway.   
    * Compatibility
      * Themida Versions 2.x to 3.x 
      * WinLicense Versions 2.x to 3.x 
      * CodeVirtualizer Versions 2.x to 3.x 
  * [Macro Entry Identifier (Reversal Approach)](https://github.com/quosego/analysis.oreans/blob/master/Scripts/ida/oreans_macro_entry_identifier_reversal.py)
    * About
      * Used to find possible macro entries created by Oreans. Knowing the locations can help give an overview of how much protection is used, where to focus, where to remove unnessasary "buffers" and help in restoring the original code. The reversal approach is an accurate and reliable method that uses an adopted reverse traversal approach from the 2016* [backward bounded DSE](https://www.ieee-security.org/TC/SP2017/papers/220.pdf) slide within the presentation by [Robin David & Sébastien Bardin](http://www.robindavid.fr/publications/BHEU16_Robin_David.pdf).
    * Compatibility
      * Themida Versions 2.x to 3.x 
      * WinLicense Versions 2.x to 3.x 
      * CodeVirtualizer Versions 2.x to 3.x 
  * [Anti-Debugger Blacklist Identifier](https://github.com/quosego/analysis.oreans/blob/master/Scripts/ida/oreans_anti_debug_blacklist_identifier.py)
    * About
      * Used to find possible debugger names that are blocked by Oreans. Knowing these locations can help when identifying regions of Oreans, improve the understanding of features used by Oreans, and bypass certain debug checks.
    * Compatibility
      * Themida Version 2.x
      * WinLicense Version 2.x
      * CodeVirtualizer Version 2.x
  * TBA
* [GHIDRA](https://ghidra-sre.org/)
  * TBA

[ref-SELF]: https://github.com/quosego
