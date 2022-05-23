# HackerSchool CTF writeups (PT)
## Em construção....

[Weekend CTF Tournament (21 & 22 de maio 2022)](https://ctf.hackerschool.io)

## Info
Este repo contem alguns writeups das nossas soluções nas CTF's da HS.
- Lugar (equipa): 5º
- Pontos: 1760
- Equipa: 888海日人,,
    - [roby](https://github.com/roby2014)
    - [mura](https://github.com/)
    - [kardoso](https://github.com/diogocardoso28)
    - [sn0wygecko](https://github.com/eduardoervideira) 

## Challenges ([link](https://ctf.hackerschool.io/challenges))

### forensics
- Nem tudo é o que parece [[Solved]](#) 
- Poema de neve [[Solved]](#)
- Receita do Doutor
- HSB Em Estreóides

### rev
- Introdução GDB [[Solução]](#introdução-gdb)
- Estás a olhar? [[Solução]](#estás-a-olhar)
- Nunca me Reverás [[Solved]](#)
- Rede Neuronal Personalizada
- Encontra o Caminho

### web
- Concurso HS Infantil [[Solved]](#)
- Donald [[Solved]](#)
- Verificador HS [[Solved]](#)
- HSI
- Concurso HS

### osint
- O RAM do Hacker [[Solved]](#)
- Atividades do RAM [[Solved]](#)
- RAM Fugitivo [[Solved]](#)
  
### pwn
- Borda Fora [[Solved]](#)

### misc
- Sanity check [[Solved]](#)
- Amigos Dobráveis [[Solved]](#)
- HS Jail [[Solved]](#)
- Testamento
- Detetor de Palavrões
- HS Jail 3
- HS Jail 2
- HS Bem Temperada

### crypto
- Sanity RSA
- RSA Pequena
- Cozinhas com a HS
- Matemática do Secundário
- HSBanco
- EGG PQ
- Diabólico polinómio
- DEHS

# Soluções

## Introdução GDB
![challenge](/assets/introducao_gdb.png)

```
$ ./introducao_gdb
Bem-vindo! Fiz um pequeno verificador de passwords eheh, consegues adivinhar?
ola
Hey! Isso não está bem, ai ai ai :(  
```

Eu sei que o objetivo era, como o título diz, utilizar o GDB, mas antes de saltar para essa parte, utilizei o comando `strings` para ver se conseguia encontrar a string crua no binário.
Utilizando `strings introducao_gdb`, consegui encontrar:
```
HS{y3yyyH
y_b0m_trH
4b4lh0_vH
4m0s_4_sH
3ri0_?}
```
Fácil xD.

Podemos também resolver utilizando o GDB, o que faria eu era o seguinte:
Primeiro ia verificar a função main:
```
gef➤  disas main
Dump of assembler code for function main:
   0x0000555555555165 <+0>:	push   rbp
   0x0000555555555166 <+1>:	mov    rbp,rsp
   0x0000555555555169 <+4>:	sub    rsp,0x60
   0x000055555555516d <+8>:	lea    rdi,[rip+0xe94]        # 0x555555556008
   0x0000555555555174 <+15>:	call   0x555555555030 <puts@plt>
   0x0000555555555179 <+20>:	lea    rax,[rbp-0x30]
   0x000055555555517d <+24>:	mov    rsi,rax
   0x0000555555555180 <+27>:	lea    rdi,[rip+0xecf]        # 0x555555556056
   0x0000555555555187 <+34>:	mov    eax,0x0
   0x000055555555518c <+39>:	call   0x555555555050 <__isoc99_scanf@plt>
   0x0000555555555191 <+44>:	movabs rax,0x79797933797b5348
   0x000055555555519b <+54>:	movabs rdx,0x72745f6d30625f79
   0x00005555555551a5 <+64>:	mov    QWORD PTR [rbp-0x60],rax
   0x00005555555551a9 <+68>:	mov    QWORD PTR [rbp-0x58],rdx
   0x00005555555551ad <+72>:	movabs rax,0x765f30686c346234
   0x00005555555551b7 <+82>:	movabs rdx,0x735f345f73306d34
   0x00005555555551c1 <+92>:	mov    QWORD PTR [rbp-0x50],rax
   0x00005555555551c5 <+96>:	mov    QWORD PTR [rbp-0x48],rdx
   0x00005555555551c9 <+100>:	movabs rax,0x7d3f5f30697233
   0x00005555555551d3 <+110>:	mov    QWORD PTR [rbp-0x40],rax
   0x00005555555551d7 <+114>:	mov    BYTE PTR [rbp-0x38],0x0
   0x00005555555551db <+118>:	mov    DWORD PTR [rbp-0x4],0x0
   0x00005555555551e2 <+125>:	jmp    0x555555555232 <main+205>
   0x00005555555551e4 <+127>:	lea    rdx,[rbp-0x60]
   0x00005555555551e8 <+131>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00005555555551eb <+134>:	cdqe
   0x00005555555551ed <+136>:	add    rdx,rax
   0x00005555555551f0 <+139>:	lea    rcx,[rbp-0x30]
   0x00005555555551f4 <+143>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00005555555551f7 <+146>:	cdqe
   0x00005555555551f9 <+148>:	add    rax,rcx
   0x00005555555551fc <+151>:	movzx  eax,BYTE PTR [rax]
   0x00005555555551ff <+154>:	movzx  edx,BYTE PTR [rdx]
   0x0000555555555202 <+157>:	movzx  eax,al
   0x0000555555555205 <+160>:	movzx  edx,dl
   0x0000555555555208 <+163>:	sub    eax,edx
   0x000055555555520a <+165>:	mov    DWORD PTR [rbp-0x8],eax
   0x000055555555520d <+168>:	cmp    DWORD PTR [rbp-0x8],0x0
   0x0000555555555211 <+172>:	je     0x55555555522e <main+201>
   0x0000555555555213 <+174>:	lea    rdi,[rip+0xe46]        # 0x555555556060
   0x000055555555521a <+181>:	mov    eax,0x0
   0x000055555555521f <+186>:	call   0x555555555040 <printf@plt>
   0x0000555555555224 <+191>:	mov    edi,0x0
   0x0000555555555229 <+196>:	call   0x555555555060 <exit@plt>
   0x000055555555522e <+201>:	add    DWORD PTR [rbp-0x4],0x1
   0x0000555555555232 <+205>:	cmp    DWORD PTR [rbp-0x4],0x26
   0x0000555555555236 <+209>:	jle    0x5555555551e4 <main+127>
   0x0000555555555238 <+211>:	lea    rdi,[rip+0xe47]        # 0x555555556086
   0x000055555555523f <+218>:	mov    eax,0x0
   0x0000555555555244 <+223>:	call   0x555555555040 <printf@plt>
   0x0000555555555249 <+228>:	nop
   0x000055555555524a <+229>:	leave
   0x000055555555524b <+230>:	ret
End of assembler dump.
```

Podemos ver que no endereço de memória `0x000055555555520d` acontece o seguinte:
```
0x000055555555520d <+168>:	cmp    DWORD PTR [rbp-0x8],0x0
0x0000555555555211 <+172>:	je     0x55555555522e <main+201>
```
O que consigo interpretar é, fazemos uma comparação e caso seja igual (`je` *= jump if equal*), saltamos para `0x55555555522e`. Estou a assumir que isto compara a string que enviamos como input e a flag original.

Se metermos um breakpoint antes de saltar (`b *0x0000555555555211`), podemos observar o seguinte:
![challenge](/assets/introducao_gdb_2.png)
Boom, a string está vísivel no stack.

## Estás a olhar?
![challenge](/assets/estas_a_olhar.png)

```
$ ./estas_a_olhar
Flag aqui? nunca #HS 
```

Desta vez, o objetivo era utilizar o comando `strings` mesmo, mas depois de não sei quanto tempo a experimentar os vários argumentos, não consegui chegar lá só com o comando.
Portanto armei-me em trolha e fui dar disassembly ao binário:

`objdump estas_a_olhar -d -M intel` 
*(intel syntax porque ATT dá-me dores de cabeça)*

Olhando para a função main, temos o seguinte:
```
0000000000001135 <main>:
    1135:	55                   	push   rbp
    1136:	48 89 e5             	mov    rbp,rsp
    1139:	48 83 ec 50          	sub    rsp,0x50
    113d:	48 c7 45 f2 00 00 00 	mov    QWORD PTR [rbp-0xe],0x0
    1144:	00
    1145:	c7 45 fa 00 00 00 00 	mov    DWORD PTR [rbp-0x6],0x0
    114c:	66 c7 45 fe 00 00    	mov    WORD PTR [rbp-0x2],0x0
    1152:	c7 45 ee 48 53 7b 00 	mov    DWORD PTR [rbp-0x12],0x7b5348
    1159:	c7 45 ea 77 34 31 00 	mov    DWORD PTR [rbp-0x16],0x313477
    1160:	c7 45 e6 74 5f 73 00 	mov    DWORD PTR [rbp-0x1a],0x735f74
    1167:	c7 45 e2 30 5f 00 00 	mov    DWORD PTR [rbp-0x1e],0x5f30
    116e:	c7 45 de 73 74 72 00 	mov    DWORD PTR [rbp-0x22],0x727473
    1175:	c7 45 da 31 6e 67 00 	mov    DWORD PTR [rbp-0x26],0x676e31
    117c:	c7 45 d6 73 5f 77 00 	mov    DWORD PTR [rbp-0x2a],0x775f73
    1183:	c7 45 d2 30 72 00 00 	mov    DWORD PTR [rbp-0x2e],0x7230
    118a:	c7 45 ce 6b 73 5f 00 	mov    DWORD PTR [rbp-0x32],0x5f736b
    1191:	c7 45 ca 30 72 00 00 	mov    DWORD PTR [rbp-0x36],0x7230
    1198:	c7 45 c6 5f 6e 30 00 	mov    DWORD PTR [rbp-0x3a],0x306e5f
    119f:	c7 45 c2 74 3f 3f 00 	mov    DWORD PTR [rbp-0x3e],0x3f3f74
    11a6:	c7 45 be 3f 7d 00 00 	mov    DWORD PTR [rbp-0x42],0x7d3f
    11ad:	48 8d 3d 50 0e 00 00 	lea    rdi,[rip+0xe50]        # 2004 <_IO_stdin_used+0x4>
    11b4:	b8 00 00 00 00       	mov    eax,0x0
    11b9:	e8 72 fe ff ff       	call   1030 <printf@plt>
    11be:	90                   	nop
    11bf:	c9                   	leave
    11c0:	c3                   	ret
    11c1:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    11c8:	00 00 00
    11cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
```

OK, e agora????

Reparei que antes de `call   1030 <printf@plt>` (suponho que seja a instrução que printa o *"Flag aqui? nunca #HS"*), temos muitos `movs` de valores estranhos em hex.
Portanto, olhei para `mov    DWORD PTR [rbp-0x12],0x7b5348` e fui converter `0x7b5348` para texto, o resultado foi `{SH`, que por acaso, é o ínicio do formato da flag (`HS{.....}`). Depois disto, percebi que a flag está separada pelas várias instruções em valor hexadecimal (em little-endian! Temos que inverter a ordem dos bytes), portanto fui converter todos os valores (xD):
```
0x7b5348  ->  \x7b\x53\x48 = {SH  ->  \x48\x53\x7b = HS{
0x313477  ->  \x31\x34\x77 = 14w  ->  \x77\x34\x31 = w41
0x735f74  ->  \x73\x5f\x74 = s_t  ->  \x74\x5f\x73 = t_s
0x5f30    ->  \x5f\x30     = _0   ->  \x30\x5f     = 0_
0x727473  ->  \x72\x74\x73 = rts  ->  \x73\x74\x72 = str
0x676e31  ->  \x67\x6e\x31 = gn1  ->  \x31\x63\x67 = 1ng
0x775f73  ->  \x77\x5f\x73 = w_s  ->  \x73\x5f\x77 = s_w
0x7230    ->  \x72\x30     = r0   ->  \x30\x72     = 0r
0x5f736b  ->  \x5f\x73\x6b = _sk  ->  \x6b\x73\x5f = ks_
0x7230    ->  \x72\x30     = r0   ->  \x30\x72     = 0r
0x306e5f  ->  \x30\x6e\x5f = 0n_  ->  \x5f\x6e\x30 = _n0
0x3f3f74  ->  \x3f\x3f\x74 = ??t  ->  \x74\x3f\x3f = t??
0x7d3f    ->  \x7d\x3f     = }?   ->  \x3f\x7d     = ?}
```
Resultado final: `{HS{w41t_s0_str1ngs_w0rks_0r_n0t???}`

Acabei por descobrir no final da competição que era só executar `strings -n 2` LOL.

