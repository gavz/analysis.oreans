# 🔎 Analysis of Oreans - Version 3 - Themida - x32

#### Advanced API-Wrapping


## Disclaimer

This write-up is focused on the analysis of an executable using Themida 3.0.8.0. Documentation provided may be changed at any given time.

## Author

* ["quosego"][ref-SELF]

## Assumptions

Going into the analysis of Themida's new API wrapping we must first assume the following:

* We have access to the ".text" segment.
* We have access to the ".rdata" segment.
* We have access to the ".themida" segment.
* We have the REAL OEP address.
* We have the IAT base address.
* We have the IAT size.

The following address table will also be referenced in this write-up.

```
Address  Size     Info                                                Content                    Type Protection Initial
00400000 00001000  apiwrappped.exe                                                               IMG  -R---      ERWC-
00401000 00004000  ".text"                                            Executable code            IMG  ER---      ERWC-
00405000 00001000  ".rdata"                                           Read-only initialized data IMG  ERW--      ERWC-
00406000 00001000  ".idata"                                           Import tables              IMG  -RW--      ERWC-
00407000 002BC000  ".themida"                                                                    IMG  ERW--      ERWC-
```

Now, we must also consider the methods that could be used to access the IAT. We must assume:

* PREFIX
  * Themida accesses the IAT while initializing its Lightning VM upon entry.

* POSTFIX
  * Normal Code / "Virtualized" Code accesses the IAT once past the Lightning VM phase.

Both methods end up accessing the same pre-obfuscated code regions. The choice of applying either method is up to the reader depending on their own approaches.

For this analysis I will be using the POSTFIX approach.

## Pointer Calls

After successfully landing on the REAL OEP address, searching for "FF 15 ?? ?? ?? ??" within the ".text" segment yields most likely calls to the IAT.

```asm
00401042 | 8D85 F8FEFFFF            | lea eax,dword ptr ss:[ebp-108]
00401048 | 50                       | push eax
00401049 | FF15 18504000            | call dword ptr ds:[405018]   ; <----- IAT CALL
```

Following, 00405018, into the DUMP leads us to:

```asm
00405018:  0047A4D1 00000000 205D3F5B 73657270
```

It contains the 32bit address, 0047A4D1, that leads us to the main "obfuscated api entry" jump.

```asm
0047A4D1 | E9 CB0C1F00              | jmp 0066B1A1
```

## IAT Pointers

Alternatively, after landing on the REAL OEP address, looking up the IAT base address can also provide the list of "API Wrapped" imports.

```asm
00405000:  0042D749 004F045E 004AAEAE 00472079
00405010:  004143AF 00000000 0047A4D1 00000000
```

```asm
0042D749 | E9 B4142600              | jmp 0068EC02
```

```asm
004F045E | E9 F6D11800              | jmp 0067D659
```

```asm
004AAEAE | E9 28501E00              | jmp 0068FEDB
```

```asm
00472079 | E9 85C02000              | jmp 0067E103
```

```asm
004143AF | E9 FC452600              | jmp 006789B0
```

```asm
0047A4D1 | E9 CB0C1F00              | jmp 0066B1A1
```

## Following IAT Entries

Entering an IAT "API Wrapped" entry, for example, 0047A4D1, we are greeted with a series of instruction obfuscations and jumps hopping around at first glance "randomly". If we keep following, we will end up at an important sequence of instructions that sticks out like a sore thumb.

```asm
006721D3 | E8 F5BFD9FF              | call 0040E1CD
006721D8 | E9 19900000              | jmp 0067B1F6
```

For now, skip over the call and follow the continuing jumps until we hit a return.

```asm
0066ECBD | C3                       | ret
```

Congratulations! We in theory skimmed through the entire "API Wrapping". But how?

## API Wrapping Obfuscation

Following through 0047A4D1 -> 0066ECBD all blocks ended with "jmp imms" until reaching the return. We can now safely assume the API wrapper acts as a "MUTATION MACRO" also known as oreans non-virtualized obfuscation macro since we did not encounter any spinlocks or pattern-based "landing strip" returns that would indicate any additional complexity. Now, we can approach solving this obfuscated IAT region with the usage of deobfuscation (branch optimization, pattern-based simplification, subexpression elimination, constant propagation and arithmetic optimization) and static analysis.

By extracting all instructions in each jump block (not including jump instructions) and lining them into a list we are then able to recreate an obfuscated function.

```asm
0x47a4d1:

push edx
mov edx,esp
push ebx
mov dword ds:[esp],eax
mov eax,0x4fec3100
sub eax,0x4fec30fc
push edi
mov edi,0x77f64fb6
sub edx,edi
pop edi
add edx,eax
add edx,0x77f64fb6
pop eax
sub edx,4
xchg dword ds:[esp],edx
pop esp
sub esp,4
mov dword ds:[esp],esi
mov esi,esp
add esi,4
sub esi,4
push esi
push dword ds:[esp+0x4]
pop esi
pop dword ds:[esp]
pop esp
mov dword ds:[esp],eax
mov dword ds:[esp],ebx
push edx
mov dword ds:[esp],ebp
mov dword ds:[esp],0x788e8ae2
mov dword ds:[esp],ebp
mov dword ds:[esp],eax
push 0x2bc0add1
mov dword ds:[esp],ebx
mov ebx,esp
add ebx,4
push edx
mov edx,4
sub ebx,0x1ebf1ac1
sub ebx,edx
add ebx,0x1ebf1ac1
pop edx
xchg dword ds:[esp],ebx
pop esp
mov dword ds:[esp],ebp
call  0x40e1cd
push 0x44d6c
push dword ds:[esp]
pop eax
push eax
mov eax,esp
add eax,4
add eax,4
xchg dword ds:[esp],eax
mov esp,dword ds:[esp]
push dword ds:[ebp+eax+0x0]
push dword ds:[esp]
pop eax
push edx
mov dword ds:[esp],eax
mov eax,esp
add eax,4
add eax,4
xchg dword ds:[esp],eax
pop esp
push edi
mov edi,esp
add edi,4
sub edi,4
xchg dword ds:[esp],edi
pop esp
mov dword ds:[esp],edx
mov dword ds:[esp],ebx
mov dword ds:[esp],eax
push ecx
mov ecx,0x72fe31c1
push esi
mov esi,0x4ddfdf69
inc esi
sub esi,0x7efff415
not esi
and esi,0x579faeb3
xor esi,0xeefffb5d
add ecx,esi
mov esi,dword ds:[esp]
add esp,4
inc ecx
add ecx,0x77f9ad9c
dec ecx
push edi
mov edi,0x76df66d6
add edi,0xf5fc65a5
add ecx,edi
pop edi
xor ecx,0x2b1feaf4
sub eax,ecx
pop ecx
push ebx
push ecx
mov ecx,0x5cb395ff
add ecx,0x3f7b9a80
xor ecx,0x6bc7a64b
xor ecx,0x6fb5159b
add ecx,0x76bedc85
push eax
mov eax,0x3af8e784
sub eax,0x29f022e
add ecx,eax
pop eax
push ecx
pop ebx
mov ecx,dword ds:[esp]
add esp,4
shr ebx,3
and ebx,0x6dbaa90f
xor ebx,0x3e9b3fb
xor eax,ebx
pop ebx
push dword ds:[esp]
mov ebx,dword ds:[esp]
add esp,4
push ebp
mov ebp,esp
add ebp,4
add ebp,4
xchg dword ds:[esp],ebp
mov esp,dword ds:[esp]
mov dword ds:[esp+0xc],eax
push dword ds:[esp]
mov ebp,dword ds:[esp]
push ecx
mov ecx,esp
push eax
mov eax,4
add ecx,eax
pop eax
add ecx,4
xchg dword ds:[esp],ecx
pop esp
add esp,4
push dword ds:[esp]
pop eax
push ebx
mov ebx,esp
push eax
mov eax,0x7dff276a
not eax
shl eax,4
sub eax,0x200d894c
add ebx,eax
pop eax
push esi
mov esi,4
add ebx,esi
pop esi
xchg dword ds:[esp],ebx
pop esp
push dword ds:[esp]
pop ebx
push edx
push esp
pop edx
add edx,4
add edx,4
xor edx,dword ds:[esp]
xor dword ds:[esp],edx
xor edx,dword ds:[esp]
pop esp
ret
```

Now, we should to look into the call found in 006721D3 as it will serve as a important feature within our obfuscated function.

```asm
0x40e1cd:

call 0x40e1d2
0040e1d2: pop ebp
sub ebp, 0x71d2
ret
```

## Deobfuscation Approaches

Now, we need to simplify our functions using some deobfuscation techniques. There are several approaches for deobfuscating and is ultimately up to the reader. The following are some example approaches that could be considered used with this sample.


### Algebraic

* The following can be seen using arithmetic obscurity with immutable values to a single register. Using algebraic laws during a [peephole optimization][ref-DEO-peephole] approach would work in this situation.

  ```asm
  ; input
  mov ecx,0x5cb395ff
  add ecx,0x3f7b9a80
  xor ecx,0x6bc7a64b
  xor ecx,0x6fb5159b
  add ecx,0x76bedc85
  ```
  ```
  eax = (((0x5cb395ff + 0x3f7b9a80) ⊕ 0x6bc7a64b) ⊕ 0x6fb5159b) + 0x76bedc85
  ```
  ```asm
  ; output
  mov eax, 0xF1C6034
  ```


### Algorithmic

* The following could be deobfuscated with a pattern based approach as it can be easily identified using the [XOR swap algorithm][ref-DEO-xorswap].

  ```asm
  ; input
  xor edx,dword ds:[esp]
  xor dword ds:[esp],edx
  xor edx,dword ds:[esp]
  ```
  ```
  edx ⊕ dword ds:[esp]
  dword ds:[esp] ⊕ edx
  edx ⊕ dword ds:[esp]
  ```
  ```asm
  ; output
  xchg dword ds:[esp],edx
  ```


### Stack

* A pattern based approach or stack analysis during a [peephole optimization][ref-DEO-peephole] approach could re-interpret the stack movements as a valid transferring operation.

  ```asm
  ; input
  push esp
  pop edx
  ```
  ```asm
  ; output
  mov edx, esp
  ```

* A pattern based approach or stack analysis during a [peephole optimization][ref-DEO-peephole] approach could re-interpret the stack movements as a null sequence since nothing would be changed upon execution.

  ```asm
  ; input
  push edi
  pop edi
  ```
  ```asm
  ; output
  nop
  nop
  ```

* The following transfer operation could be simplified with a pattern based approach or stack analysis during a [peephole optimization][ref-DEO-peephole] approach as it can be re-interpreted as a stack popping operation.

  ```asm
  ; input
  mov esp,dword ds:[esp]
  ```
  ```asm
  ; output
  pop esp
  ```

* Stack analysis during a [peephole optimization][ref-DEO-peephole] approach could be used to identify null sequences.

  ```asm
  ; input
  push dword ds:[esp]
  mov ebx,dword ds:[esp]
  add esp,4
  ```
  ```asm
  ; output
  mov ebx,dword ds:[esp]
  ```


## API Wrapping Simplified

First, we should simplify the called function 0x40e1cd since it is quite small. Which translates roughly into:

```asm
0x40e1cd:

mov ebp, 0x407000
ret
```

Next, we should optimize 0x47a4d1, which translates roughly into:

```asm
0x47a4d1:

sub esp,4
push ebx
push eax
push ebp
call  0x40e1cd
mov eax, 0x44d6c
mov eax, dword ds:[eax+ebp]
push eax
sub eax,0x7ccc4123
xor eax,0xb433bfa
pop ebx
mov dword ds:[esp+0xc],eax
pop ebp
pop eax
pop ebx
ret
```

Now, after a few more cycles we are finally able to connect the dots.

If you haven't noticed in 0x40e1cd it always happens to be a mov of the base address of the ".themida" segment to the ebp register which is used with eax to point an address storing a "crypted" address (0xFA43C24D). 

```
[eax(0x44d6c) + ebp(0x407000)] = [0x44bd6c] = 0xFA43C24D
```

Applying the following arithmetic then provides us with our import address.

```
((0xFA43C24D - 0x7ccc4123) ^ 0xb433bfa) = 0x7634BAD0 == wvsprintfA
```

```asm
0x47a4d1:

sub esp,4
push ebx
push eax
push ebp
mov eax, dword ds:[0x44bd6c] ; [eax(0x44d6c) + ebp(0x407000)] = 
                             ; [0x44bd6c] -> 0xFA43C24D
push eax                     ; 0xFA43C24D
sub eax,0x7ccc4123           ; 0x7D77812A
xor eax,0xb433bfa            ; 0x7634BAD0 <- import address wvsprintfA
pop ebx
mov dword ds:[esp+0xc],eax   ; wvsprintfA
pop ebp
pop eax
pop ebx
ret
```

```asm
0044BD6C:  FA43C24D 92545BAC 8947DF14 63BF450C  
0044BD7C:  8684CD6E 0000B186 00000000 00000000  
```

Thus after testing with various different configurations and virtualizations we can see and conclude Advanced API-Wrapping consists of a static 3 step process.

+  Finding The Themida Section's Base Address and Storage Offset to obtain the Encrypted Address 

```[eax(0x44d6c) + ebp(0x407000)] = [0x44bd6c] = 0xFA43C24D```

+  Applying Operation 1 against the Encrypted Address to obtain the Relative Local Address

```0xFA43C24D - 0x7ccc4123 = 0x7D77812A```

+  Applying Operation 2 against the Relative Local Address to obtain the Real Import Address 

```0x7D77812A ^ 0xb433bfa = 0x7634BAD0 == wvsprintfA```


## Conclusion

<img src="https://render.githubusercontent.com/render/math?math=(A - B) \oplus C = ?">

So all together, Each obfuscated IAT entry consists of decrypting an encrypted address at a relative location with 2 "hard-coded" keys. That large obfuscated IAT "API Wrapper" function is really just roughly:

```asm
0x47a4d1:

mov eax, 0x7634BAD0         ; wvsprintfA
mov dword ds:[esp], eax
ret
```

Which could also be expressed as:

```asm
0x47a4d1:

jmp 0x7634BAD0              ; wvsprintfA
```

Rinse and repeat for the remaining entries and patch the correct addresses then "API Wrapping" will be fully removed.

Long story short, Themida's "API Wrapping" is [*NOT SUPERHARD*][ref-SLIMv_TALK] to normalize. Automating can be done faster than the [30-40 minutes][ref-SLIMv_TIME] it took for [slimv0x00][ref-SLIM] to use taint analysis to identify the correct imports. The sample used in this documentation was able to be interpreted in less than five seconds without the usage of taint analysis.

## Note

There is a even simpler method to restore "Advanced API Wrapping" Keep watch!



[ref-DEO-peephole]: https://en.wikipedia.org/wiki/Peephole_optimization
[ref-DEO-xorswap]: https://en.wikipedia.org/wiki/XOR_swap_algorithm


[ref-SELF]: https://github.com/quosego
[ref-SLIM]: https://github.com/slimv0x00
[ref-SLIMv_TALK]: https://github.com/slimv0x00/POC_2019_WhateverTalk
[ref-SLIMv_TIME]: https://github.com/slimv0x00/POC_2019_WhateverTalk/files/3634566/Log_API_wrapping.txt