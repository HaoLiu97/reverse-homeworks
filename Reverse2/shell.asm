code segment
assume cs:code
shell:
   call next
next:
   pop bx; BX=next������ʱ��ʵ��ƫ�Ƶ�ַ
   sub bx, offset next-offset shell; bx=main������ʱ��ʵ��ƫ�Ƶ�ַ
;���ض�λ
;(1)���������׶ε�ַ
;����տ�ʼ����ʱds=es=psp�ε�ַ
;����׶ε�ַ=ds��es+10h
   mov bp, ds; mov bp, es
   add bp, 10h; bp�����׶ε�ַ

;����
   push es

   mov dx, bp; dxΪ�׶ε�ַ
   mov es, dx; esΪ�׶ε�ַ
   xor di, di
   mov ax, cs
   ;sub ax, bp; �ε�ַ��
   mov cx, bx; cxΪѭ������

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

;(2)����ض�����
   mov cx, cs:[bx+head+0]
   cmp cx, 0
   jz sssp; ����ض�λ����Ϊ0��������
;(3)��cs:siָ���ض�λ��
   lea si, [bx+head+0Ah]
;(4)ѭ����λ
   push es; ����es��ԭֵ
reloc_next:
   mov di, cs:[si]; �ض�λ���ƫ��
   mov dx, cs:[si+2]; �ض�λ���delta_�ε�ַ
   add dx, bp; dx���ض�λ��Ķε�ַ
   mov es, dx
   add es:[di], bp
   add si, 4
   dec cx
   jnz reloc_next
   pop es; �ָ�es��ԭֵ
;(5)����ss:sp
sssp:
   mov dx, cs:[bx+head+2]
   add dx, bp
   mov sp, cs:[bx+head+4]
   mov ss, dx
;(6)����cs:ip
   mov dx, cs:[bx+head+8]
   add dx, bp
   push dx
   push word ptr cs:[bx+head+6]
   retf
isFinish:; �жϽ���������cx == 0��es == ax��ͨ��zf���ݽ��
   cmp cx, 0
   jz cx0
   ret
   cx0:
   	mov si, es
      cmp si, ax
      ret

head label word; head��һ��������, ����Ϊword,
               ; ����ֻ�����ּ���ַ,û��ֵ,
               ; �����ռ�ڴ�ռ�
;head+00 �ض�λ����; word
;head+02 delta_ss
;head+04 sp
;head+06 ip
;head+08 delta_cs
;head+0A �ض�λ��
code ends
end shell