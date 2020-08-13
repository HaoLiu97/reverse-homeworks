code segment
assume cs:code
shell:
   call next
next:
   pop bx; BX=next的运行时的实际偏移地址
   sub bx, offset next-offset shell; bx=main在运行时的实际偏移地址
;做重定位
;(1)计算程序的首段地址
;程序刚开始运行时ds=es=psp段地址
;因此首段地址=ds或es+10h
   mov bp, ds; mov bp, es
   add bp, 10h; bp就是首段地址

;解密
   push es

   mov dx, bp; dx为首段地址
   mov es, dx; es为首段地址
   xor di, di
   mov ax, cs
   ;sub ax, bp; 段地址差
   mov cx, bx; cx为循环次数

decrypt:
   xor byte ptr es:[di], 33h
   dec cx
   call isFinish
   jz decrypt_end
   inc di
   jz esadd
   jmp decrypt
   esadd:
   	  mov dx, es
   	  mov si, 1000h
   	  add dx, si
      mov es, dx
      call isFinish
      jz decrypt_end
      jmp decrypt

decrypt_end:
   pop es

;(2)获得重定项数
   mov cx, cs:[bx+head+0]
   cmp cx, 0
   jz sssp; 如果重定位项数为0，则跳过
;(3)让cs:si指向重定位表
   lea si, [bx+head+0Ah]
;(4)循环定位
   push es; 保护es的原值
reloc_next:
   mov di, cs:[si]; 重定位项的偏移
   mov dx, cs:[si+2]; 重定位项的delta_段地址
   add dx, bp; dx是重定位项的段地址
   mov es, dx
   add es:[di], bp
   add si, 4
   dec cx
   jnz reloc_next
   pop es; 恢复es的原值
;(5)设置ss:sp
sssp:
   mov dx, cs:[bx+head+2]
   add dx, bp
   mov sp, cs:[bx+head+4]
   mov ss, dx
;(6)设置cs:ip
   mov dx, cs:[bx+head+8]
   add dx, bp
   push dx
   push word ptr cs:[bx+head+6]
   retf
isFinish:; 判断结束条件，cx == 0且es == ax，通过zf传递结果
   cmp cx, 0
   jz cx0
   ret
   cx0:
   	mov si, es
      cmp si, ax
      ret

head label word; head是一个变量名, 类型为word,
               ; 但它只有名字及地址,没有值,
               ; 编译后不占内存空间
;head+00 重定位项数; word
;head+02 delta_ss
;head+04 sp
;head+06 ip
;head+08 delta_cs
;head+0A 重定位表
code ends
end shell