.386
.model flat, stdcall  ;32 bit memory model
.stack 100h
option casemap :none  ;case sensitive
include user32.inc
include kernel32.inc
include windows.inc 

; Directives for the linker to link libraries
includelib c:\masm32\lib\user32.lib
includelib c:\masm32\lib\kernel32.lib
.data 
	fileinfo WIN32_FIND_DATA <>
	hFile HANDLE 0
	hFFF HANDLE 0
	filename db "*.exe", 0
	filesize dd 0
	pMemory dd 0
	
	virussize dd 0
	virusEP dd 0
	virusRawAdd dd 0
	OriginalEP dd 0
	
	ReadSize dw 0
	
.code
start:
	invoke FindFirstFile,offset filename, offset fileinfo
	mov hFFF, eax
	cmp eax, 0
	je donecuring
	call cure
	
	
	nextfile:
	mov eax, offset fileinfo.cFileName
	mov edi, 0
	_loop3:
		cmp edi, 260
		je _break3
		mov cl, 0
		mov [eax], cl
		inc eax
		inc edi
		jmp _loop3
	_break3:
	
	invoke FindNextFile,hFFF, offset fileinfo
	cmp eax, 0
	je donecuring
	call cure
	jmp nextfile
	
	
	donecuring:
	invoke ExitProcess,0
	
cure:
	invoke CreateFile,offset fileinfo.cFileName, GENERIC_READ, FILE_SHARE_READ, NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	mov hFile, eax
	
	invoke GetFileSize,hFile, NULL
	mov filesize, eax
	
	invoke VirtualAlloc, NULL, filesize, MEM_COMMIT,PAGE_EXECUTE_READWRITE
	mov pMemory, eax
	
	invoke ReadFile,hFile, pMemory, filesize, NULL, NULL
	
	;check signature neu khong co thi skip
	mov eax, pMemory
	add eax, 20h
	xor ecx, ecx
	mov ch, [eax]
	cmp ch, 'H'
	jne return
	
	;xoa signature
	mov ecx, 0
	mov [eax],ecx
	
	;e_lfanew
	mov eax, pMemory
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, pMemory
	add eax, ebx
	
	;sua numberofsection
	mov eax, pMemory
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, pMemory
	add eax, ebx
	add eax, 6h
	mov bx, [eax]
	dec bx
	mov [eax], bx
	push ebx
	
	;tim cac truong trong section virus
	mov eax, pMemory
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, pMemory
	add eax, ebx
	add eax, 248
	pop ebx
	_loopsection:
		cmp ebx, 0
		je _skipsection
		add eax, 40
		dec ebx
		jmp _loopsection
	_skipsection:
	;tim den virtual size virus
	add eax, 8
	mov ebx, [eax]
	mov virussize, ebx
	;tim den virtual address / virus Entrypoint
	add eax, 4
	mov ebx, [eax]
	mov virusEP, ebx
	;tim den raw address cua virus 
	add eax, 8
	mov ebx, [eax]
	mov virusRawAdd, ebx
	; xoa section virus
	sub eax, 20
	mov edx, 0
	_loopdel:
		cmp edx, 40
		je _skiploopdel
		mov ecx, 0
		mov [eax],ecx
		inc eax
		inc edx
		jmp _loopdel
	_skiploopdel:
	
	;sua size of image -= virussize
	mov eax, pMemory
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, pMemory
	add eax, ebx
	add eax, 50h
	mov ebx , [eax]
	sub ebx, virussize
	mov [eax], ebx
	
	;sua size of header -= 100
	mov eax, pMemory
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, pMemory
	add eax, ebx
	add eax, 54h
	mov ebx , [eax]
	sub ebx, 100
	mov [eax], ebx
	
	;lay delta ep trong virus
	mov eax, pMemory
	add eax, virusRawAdd
	add eax, 0eh
	mov ecx, [eax]
	mov OriginalEP, ecx
	;tim entrypoint goc
	mov eax, OriginalEP
	sub virusEP, eax
	mov eax, virusEP
	mov OriginalEP, eax
	;sua entrypoint
	mov eax, pMemory
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, pMemory
	add eax, ebx
	add eax, 28h
	mov ebx , OriginalEP
	mov [eax],ebx
	
	;xoa code virus
	mov eax, pMemory
	add eax, virusRawAdd
	mov ebx, virussize
	delvirus:
		cmp ebx, 0
		je donedeleting
		mov ecx, 0
		mov [eax], ecx
		inc eax
		dec ebx
		jmp delvirus
	donedeleting:
	
	invoke CloseHandle, hFile
	invoke CreateFile,offset fileinfo.cFileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
	mov hFile, eax
	sub filesize, 1200h
	invoke WriteFile,hFile,pMemory, filesize, offset ReadSize, NULL
	
	invoke CloseHandle, hFile
	invoke VirtualFree,pMemory,NULL,MEM_RELEASE
	
	
	return:
	retn
	




end start
