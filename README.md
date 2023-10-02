产生原因：对比202209和202307的AFD.sys,在函数AfdNotifyRemoveIOCompletion中，202209版的windows和202307版的windows都有一步用`ProbeForWrite`函数检测一段内存区域是否在用户态，但是检测的buffer地址有0x8字节的不同，而在该漏洞patch之前，没有该检查，可以猜测202209版的buffer的检查地址可能不太正确而可能无效，而该检查的buffer与中间一步赋值有关：`**(_DWORD **)(a3 + 24) = v20;`其中应该检查的buffer是a3+24,而v20的值与`v8 = IoRemoveIoCompletion(v25, Pool2, v4, (unsigned int)v6, &v20, a1, v13, 0)`有关，其中至少Pool2,v4,v13看上去都是用户态传进去的那个unknown struct决定的，所以猜测v20的值也和user mode传入的那个struct有关~（看了一下writeup应该是IoRemoveIoCompletion调用KeRemoveQueueEx的返回值）   
而如果a3+24储存的是一个kernel-mode的地址，可能就会造成一次kernel_arbituary_write的primitive,进而用IORING利用~（利用方式：https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/）  

复现环境：Visual Studio2022编译源代码+Windows 11 202209(在Hyper-V上运行)  编译选项是x64 Release，因为在HyperV有vcruntime140.dll缺失的问题所以采用静态链接  

AFD.sys里面的函数利用链：AfdFastIOdeviceControl->AfdNotifySock->AfdNotifyRemoveIOCompletion，会把一个unknown struct的一个域赋值为一个用户态决定的地址，从而创造出一个arbitrary kernel Write-Where源语然后进而被IORing利用   

exp实现：通过**ArbitraryKernelWrite0x1**函数实现arbituary write,exp里面该函数的主要部分是复用x86matthew师傅的一个轮子来绕过Winsock直接和AFD.sys交互(轮子原本的作用是用于直接创建TCPsocket)(https://www.x86matthew.com/view_post?id=ntsockets)  
上文中实现任意地址写的是struct*AFD_NOTIFYSOCK_DATA*即上文的unknown struct,其各种组成主要是为了绕过函数调用链里的各种检查  
第一个参数，handle的创建方式是通过undocumented NT function NtCreateIoCompletion（https://securityintelligence.com/x-force/patch-tuesday-exploit-wednesday-pwning-windows-ancillary-function-driver-winsock/）  

update一下调试感受吧：感觉看上去很相似的代码在调试的时候还是会挂在奇怪的地方  
比如一开始调用_NtCreateFile的时候第一个参数传的是hSocket，然后原函数里__imp_ObReferenceObjectByHandle就一直返回负数，看了一下然后又定义了一个handle来作为_NtCreateFile和_NtDeviceIoControlFile的参数（这两个函数感觉主要是和afd.sys交互用的 可以参考那个x86matthew的文章）  
还有一开始没调用NtSetIOCompletion然后那个IORemoveIOCompletion检查过不了..所以又参考了一波https://securityintelligence.com/x-force/patch-tuesday-exploit-wednesday-pwning-windows-ancillary-function-driver-winsock/的做法..   
然后在shadow群里提的符号表加载不了的求助，发现原因竟然是跑Windbg的电脑没开梯子，所以连不上在线的符号表  
最后是Windbg来debugHyper-V上的程序，不用像microsoft learn里面的那样复杂~，大概bcdedit /debug on; bcdedit /dbgsettings net hostip:（主机上的Ethernet default switch的ipv4地址） port:50001 key:1.2.3.4输进Hyper-V命令行就行了  
在那个zip里面是复现用的visual studio的完整project  

最后特别谢谢婷婷姐和帮忙troubleshooting windbg的mimi学长~  