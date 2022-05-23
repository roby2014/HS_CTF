# HackerSchool CTF writeups (PT)

[Weekend CTF Tournament (21 & 22 de maio 2022)](https://ctf.hackerschool.io)



## Info
Este repo contem alguns writeups das nossas soluções nas CTF's da HS.
- Lugar (equipa): 5º
- Pontos: 1760
- Equipa: 888海日人,,
    - [roby](https://github.com/roby2014)
    - [mura](https://github.com/)
    - [kardoso](https://github.com/)
    - [sn0wygecko](https://github.com/) 

## Challenges ([link](https://ctf.hackerschool.io/challenges))

### forensics
- Nem tudo é o que parece [[Solved]](#) 
- Poema de neve [[Solved]](#)
- Receita do Doutor
- HSB Em Estreóides

### rev
- Introdução GDB [[Solução]](#introdução-gdb)
- Estás a olhar? [[Solved]](#)
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

## Soluções

### Introdução GDB
![challenge](/assets/introducao_gdb.png)

Eu sei que o objetivo era, como o título diz, utiliar o GDB, mas antes de saltar para essa parte, utilizei o comando `strings` para ver se conseguia encontrar a string crua no binário.
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