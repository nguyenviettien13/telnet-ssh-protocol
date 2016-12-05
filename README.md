# telnet-ssh-protocol
Bài Tập lớn môn mạng máy tính
¬¬¬¬¬			TELNET
1: TELNET là gì ?
- BBN đã xây dựng giao thức ứng dụng Telnet cho phép sử dụng máy tính từ xa vào năm 1974.
-TELNET (viết tắt của TELecommunication NETwork cũng có thể là Terminal NETwork hay TELetype NETwork) là một giao thức mạng (network protocol) được dùng trên các kết nối với Internet hoặc các kết nối tại mạng máy tính cục bộ LAN, là một giao thức của tầng ứng dụng.
-TELNET thường được dùng để cung cấp những phiên giao dịch đăng nhập, giữa các máy trên mạng Internet, dùng dòng lệnh có tính định hướng người dùng. Tên của nó có nguồn gốc từ hai chữ tiếng Anh "telephone network" (mạng điện thoại), vì chương trình phần mềm được thiết kế, tạo cảm giác như một thiết bị cuối được gắn vào một máy tính khác
-TELNET là phương thức định hướng các byte dữ liệu.
 
Mô hình mạng TCP/IP.
-Telnet là một ứng dụng dựa trên giao thức TELNET .
 +Telnet cho phép bạn kết nối và đăng nhập vào một máy tính ở xa (trong LAN, internet ) từ đó người dùng ngồi trên một thiết bị đầu cuối có thể thông qua kết nối mạng đến một thiết bị từ xa để điều khiển ,khai thác tài nguyên của máy tính từ xa bằng câu lệnh như là đang ngồi tại máy ở xa.
 +Một máy trạm có thể thực hiện đồng thời nhiều phiên telnet đến nhiều địa chỉ IP khác nhau.
               
2. Hoạt động telnet
-Telnet hoạt động theo phiên, mỗi phiên là một kết nối truyền dữ liệu theo giao thức TCP ( truyền tin tin cậy giữa các cặp sọcket : địa chỉ IP và số hiệu cổng )thông thường số hiệu cổng mặc định là 23. 
-Telnet hoạt động theo mô hình client server trong đó client là một phần mềm chạy trên máy trạm tại chỗ mà người dùng sử dụng, phần mềm này sẽ cung cấp giao diện hiển thị để người dùng gõ lệnh điều khiển. 
-Phần server là dịch vụ chạy trên máy từ xa lắng nghe và xử lý các kết nối và câu lệnh được gửi đến từ máy trạm tại chỗ. 
-Câu lệnh ở máy trạm tại chỗ (terminal) sẽ được đóng gói bằng giao thức TCP và truyền đến địa chỉ IP của máy ở xa. Máy ở xa sẽ bóc tách gói tin đó và đọc ra câu lệnh để thực hiện. Kết quả trả về sẽ được máy từ xa đóng gói lại và gửi cho máy tại chỗ (client) . Các câu lệnh điều khiển từ xa của telnet do vậy sẽ được đóng gói và truyền song song với dữ liệu trên một mạng máy tính. Các gói tin của telnet do đó cũng được định tuyến như các gói dữ liệu để đến được máy đích và ngược lại. 
 
-Đường truyền của telnet là fullduplex( tại cùng một thời điểm có thể thực hiện song song các tác vụ gửi và nhận trên một đường truyền), cho phép cả client và server có thể nhận và phát dữ liệu đồng thời. ( Có 3 loại đường truyền : fullduplex, halfduplex và simple mode- thong tin chỉ truyền theo một chiều đã được quy định trước).
-Telnet cho phép kết nối và điều khiển nhiều thiết bị của các hãng khác nhau, thậm chí chạy các hệ điều hành khác nhau chỉ cần giữa 2 máy đó có một kết nối IP thông suốt. Để có kết nối IP đó các máy phải trong cùng một mạng hoặc ở các mạng khác nhau nhưng có thể định tuyến đến nhau được. 
.
3.Trạm làm việc ảo (NVT- Network Vitual Terminal)
 
 -Khi người sử dụng gọi Telnet, thì một chương trình ứng dụng trên máy của người sử dụng trở thành Client. Sau đó, Client này thiết lập kết nối TCP đến Server mà chúng sẽ thông tin liên lạc. Một khi kết nối đã được thiết lập, Client sẽ nhận các ký tự bàn phím của người sử dụng và gửi chúng đến Server , trong khi đó nó cũng đồng thời nhận các ký tự mà Server gửi ngược trở về và thể hiện nó lên màn hình của người sử dụng. Server phải nhận một kết nối TCP từ Client và rồi chuyển dữ liệu đi giữa kết nối TCP này và hệ điều hành cục bộ. 
- Để cho Telnet hoạt động trong càng nhiều hệ thống khác nhau càng tốt thì nó chắc chắn phải giải quyết được các yêu cầu khác nhau từ các hệ khác nhau
   VD: Một số hệ yêu cầu các dòng văn bản được kết thúc bởi ký tự ASCII carriage control (CR), những hệ khác lại yêu cầu ký tự ASCII linefeed (LF). Lại có những hệ yêu cầu chuỗi hai ký tự CR-LF.
-Để chấp nhận được nhiều hệ khác nhau, Telnet định nghĩa cách dữ liệu và các lệnh được gửi qua Internet. Định nghĩa này được gọi là Trạm ảo (Network Virtual Terminal). Trong hình dưới, phần mềm Client chuyển đổi các ký hiệu các bàn phím và chuỗi lệnh từ trạm của người sử dụng thành dạng NVT và gửi chúng tới Server. Phần mềm Server lại chuyển đổi dữ liệu và các lệnh gửi đến từ dạng NVT thành dạng mà hệ ở xa yêu cầu. Quá trình này diễn ra tương tự đối với tín hiệu trả về.
 
4. Cơ chế bảo mật và cấu hình Telnet.
4.1. Cơ chế bảo mật.
-Telnet không phải là một giao thức kết nối an toàn bởi vì nó không có  một cơ chế bảo mật và như vậy việc chuyển dữ liệu thông qua mạng internet chỉ dưới dạng văn bản thô bao gồm thông tin về cả tài khoản và mật khẩu được gửi đi trong quá trình chuyển tiếp dữ liệu.Như vậy nếu có một người ngoài nào có khả năng truy cập, hoặc đến gần được vào một bộ định tuyến (router), một bộ chuyển mạch (switch), hoặc một cổng nối (gateway) nằm trên mạng lưới, giữa hai máy chủ dùng Telnet ở trên, người đó có thể chặn các gói dữ liệu của Telnet trên đường truyền, lấy những tin tức về đăng nhập, mật khẩu (và tất cả những gì mà người gửi đã đánh máy), bằng cách sử dụng một số những công cụ phần mềm như tcpdump hoặc Wireshark.
 
- TELNET không mật mã hóa(unencrypted) các dữ liệu truyền tải qua đường dây kết nối (kể cả mật khẩu), vì thế việc nghe trộm đường truyền thông là một việc tương đối dễ dàng thực hiện. Mật khẩu lấy trộm được có thể được dùng vào những việc có mục đích hiểm độc gây ra hậu quả rất lớn về bảo mật thông tin.
- TELNET thiếu nghi thức xác thực người dùng. Nhu cầu xác thực người dùng là một nhu cầu quan trọng, đảm bảo sự giao thông giữa hai máy chủ trong cuộc, không bị một người trung gian xen vào (xin xem thêm những tấn công trung gian (Man-in-the-middle attacks).
- Dưới sự bùng nổ của phát triển Internet, Telnet ngày càng trở lên không an toàn trong một thế giới “ nguy hiểm”. Năm 1995 SSH ra đời , SSH cung cấp tất cả những chức năng đã có trong "telnet", nhưng thêm chức năng mã hóa dữ liệu, tránh cho những dữ liệu có tính nhạy cảm cao bị chặn lại và bị nghe trộm. Phương pháp xác minh, dùng khóa công khai (public key), để chứng minh một máy tính ở xa nào đấy, thực sự là máy mà mình muốn liên lạc, đã được thực hiện.
4.2: Cấu hình telnet trên router cisco 
Từ một máy tính có địa chỉ IP1 cấu hình đến router với địa chỉ IP2



-Bước 1: Tạo đường đi từ PC đến Router thông qua địa chỉ IP của hai thiết bị : IP1 ping IP2
-Bước 2: Mở cổng vty trên router để cho phép các thực thể khác truy cập đến router qua cổng này 
     		R(config)# enable password cisco
R(config)# line vty 0 4 ( Mở cổng vty từ 0 đến 4 trên router)
R(config-line)# password mmt ( Đặt password cho kết nối là “mmt”)
R(config-line)# login
-Quá trình cấu hình kết thúc , lúc này từ PC có thể truy cập đến router qua mạng không cần phải kết nối qua cổng console.


4.3: Hướng dẫn sử dụng telnet  
Ta sẽ thực hiện tel net máy từ máy vật lý sang máy ảo chạy hệ điều hành windows server 2008
+Chuẩn bị: 
-Cài windows server 2008 trên phần mềm máy ảo vmware.
-Chọn card mạng ở chế độ NAT
 
+Thực hiện
Bước 1: Cấu hình và cài đặt dịch vụ telnet server cho máy ảo
Add futures telnetservers cho máy ảo
 
  Việc ta add telnetserver service không có nghĩa là nó sẽ chạy luôn mà ta cần  start service 
 
Thêm member vào trong telnetclient_Group 
Start dịch vụ telnetclient trong window 10.
 
Kiểm tra địa chỉ máy telnetserver
 
Bắt đầu telnet tới máy chủ
 
Login vào máy server 
 
Chiếm quyền kiểm soát máy server : 
Ví dụ ta qua telnet để từ máy khách thêm một thư mục mới vào trong máy chủ
 

Sử dụng wildshark để bắt gói tin, ta thấy rõ username và password
 
=>Đây chính là lỗ hổng để những kẻ attacter tấn công và lấy căp thông tin và SSH protocol ra đời nhằm giải quyết vấn đề này.





















		SSH PROTOCOL
1.SSH PROTOCOL là gì???
1.1 Khái niệm
SSH (Secure Shell) là một giao thức mạng dùng để thiết lập kết nối mạng một cách bảo mật. SSH hoạt động ở lớp trên trong mô hình phân lớp TCP/IP. Các công cụ SSH (như là OpenSSH, …) cung cấp cho người dùng cách thức để thiết lập kết nối mạng được mã hoá để tạo một kênh kết nối riêng tư.
 

SSH (Secure Shell) là dịch vụ hỗ trợ việc quản lý Linux/Unix từ xa qua mạng, hỗ trợ chứng thực với 3 cách khác nhau: bằng password, bằng public key, và thông qua một hệ thống quản lý account tập trung (Kerberos, LDAP, ...)
Các chương trình trước đây như telnet, rlogin không sử dụng phương pháp mã hoá. Vì thế bất cứ ai cũng có thể nghe trộm thậm chí đọc, sửa đổi được toàn bộ nội dung của phiên làm việc bằng cách sử dụng một số công cụ đơn giản. Sử dụng SSH là biện pháp hữu hiệu bảo mật dữ liệu trên đường truyền từ hệ thống này đến hệ thống khác.
Mặc định dịch vụ SSH sử dụng cổng 22
1.2 Nguyên lý hoạt động
SSH làm việc thông qua 3 bước:
•	Bước 1. Định danh host – xác định định danh của hệ thống tham gia phiên làm việc SSH:
o	Máy chủ gửi khóa public tới máy trạm
o	Máy trạm sinh ra một khóa ngẫu nhiên và mã hóa khóa này bằng khóa public do máy chủ gửi tới và gửi trả lại máy chủ
o	Máy chủ giải mã khóa do máy trạm gửi tới bằng khóa private của mình và nhận được khóa của máy trạm
•	Bước 2. Mã hoá – thiết lập kênh làm việc mã hoá.
•	Bước 3. Chứng thực – xác thực người sử dụng có quyền đăng nhập hệ thống:
o	Được thực hiện trên kênh trao đổi bảo mật
o	Mỗi định danh và truy cập của người dùng được cung cấp theo nhiều cách khác nhau:
	Chứng thực rhosts: chỉ kiểm tra định danh máy trạm được liệt kê trong file rhosts (theo DNS và địa chỉ IP)
	Chứng thực mật khẩu: rất thông dụng (dùng tài khoản của hệ thống)
	Chứng thực RSA: sử dụng ssh-keygen và ssh-agent để chứng thực các cặp khóa
OpenSSH cung cấp khá nhiều tính năng để giúp cho việc truyền thông giữa 2 host trở nên an toàn. Dưới đây là một số tính năng nổi bật:
•	Khả năng mã hoá mạnh bởi việc sử dụng chuẩn mã hoá 3 DES và Blowfish: Cả 2 chuẩn mã hoá trên đều đuợc cung cấp miễn phí và sử dụng rộng rãi ở nhiều nước trên thế giới. 3DES cung cấp khả năng mã hoá chứng thực thời gian. Blowfish cung cấp khả năng mã hoá nhanh hơn. Cũng như những chuẩn mã hoá khác cả 2 chuẩn nêu trên đều cung cấp khả năng mã hoá các dữ liệu trước khi nó được đưa vào đường truyền một cách an toàn.
•	Khả năng chứng thực mạnh bởi việc sử dụng các cơ chế Public Key, mật khẩu một lần (One-Time Password - OTP), Kerberos, có tác dụng bảo vệ chống lại tính dễ tổn thương trong quá trình chứng thực bởi việc khai thác và sử dụng các kỹ thuật như: IP Spoof, DNS Spoof, Fake Router…Có 4 phương pháp chứng thực được Open SSH sử dụng :
o	Chỉ chứng thực Public Key
o	Sự chứng thực host bởi việc sử dụng Public Key kết hợp với .rhost
o	Sự chứng thực dựa trên OPT kết hợp với s/key
o	Sự chứng thực dựa trên cơ chế Kerberos
•	Mã hoá giao thức X11 cho việc sử dụng X Window: Mã hoá dữ liệu trong quá trình sử dụng X Window giữa 2 host. Được sử dụng để chống lại những cuộc tấn công từ xa nhằm vào xterm như Snooping, Hjacking…
•	Mã hoá cho quá trình chuyển đổi cổng (Port Forwarding): Cho phép quá trình chuyển đổi các port TCP/IP tới một hệ thống khác thông qua một kênh được mã hoá. Nó được sử dụng cho những giao thức Internet chuẩn không cung cấp khả năng mã hoá dữ liệu trên đường truyền như: SMTP, POP, FTP, Telnet…
•	Đại diện chuyển tiếp cho những đăng nhập vào các mạng đơn: Một Key chứng thực của người dùng có thể và thường được lưu giữ trên PC của họ, nó có thể trở thành một trạm đại diện chứng thực. Khi người sử dụng hệ thống truy cập từ một hệ thống mạng khác. Kết nối của họ sẽ được chuyển tới cho trạm đại diện chứng thực này. Nó có tác dụng cho phép người sử dụng truy cập đến hệ thống của bạn một cách an toàn từ bất kỳ hệ thống nào.
•	Nén dữ liệu: Cung cấp khả năng nén dữ liệu một cách an toàn. Nó rất có ý nghĩa trên những hệ thống mạng không được nhanh.
•	Chứng thực chung cho Kerberos và Andrew File System bằng cách sử dụng Ticket: Những người sử dụng Kerberos và AFS sẽ được cung cấp một password chung để sử dụng và truy cập 2 dịch vụ trên trong một thời gian nhất định.
OpenSSH không phải là một chương trình. Nó là một bộ các chương trình kết nối an toàn:
•	OpenSSH Client (ssh): Chương trình được sử dụng cho các đăng nhập từ xa. Với sự an toàn và mã hoá trong mỗi phiên đăng nhập ở mức độ cao.
•	Secure Copy Program (scp): Được sử dụng cho việc copy file từ xa, copy các file từ các host khác nhau trên Internet. Nó hỗ trợ username và password.
•	Secure File Transfer Program (sftp): Được sử dụng để phục các yêu cầu FTP một cách an toàn.
•	OpenSSH Deamon (sshd): Đặt OpenSSH chạy ở chế độ daemon trên các hệ thống Unix.

Câu chuyện vui giúp hiểu hơn về ssh (Tự nghĩ):
Bây giờ mình sẽ lấy ví dụ là Tôi và Bạn là hai người bạn rất thân, Bạn ở lại kinh doanh bất động sản và trở nên thành một trong những tỷ phú giàu có nhất tại Việt Nam. Còn tôi sang Singapo sống cảnh thất nghiệp.
Một ngày đẹp trời tôi quyết định gửi cho bạn một “thông điệp vay bạn vài tỷ”, vậy làm thế nào để đảm bảo rằng thông điệp bạn gửi đến đúng người, và tiền mà bạn gửi cho tôi đến được với tôi. Giải pháp là gì?
Tôi bèn kể câu chuyện với ông thầy dạy mạng máy tính tôi và ông ấy cho tôi một đống tài liệu về một loại giao thức và nói bạn sẽ biết được cách giải quyết cách vấn đề.
Đọc một hồi và tôi biết được cái giao thức mà ông thầy nói là “SSH protocol”, và tôi quyết định sẽ áp dụng nó vào trong việc chuyển tiền của chúng ta.
Giờ thế này nhé, Bạn (Server) sẽ gửi cho tôi một cái VaLy loại sịn và đảm bảo chỉ Bạn mới có Key để mở. 
Chiếc VaLy được gửi được gửi đến Tôi và Tôi cũng có một chiếc Hòm tương tự, cũng đảm bảo rằng chiếc Hòm chỉ mình tôi mở được.
Tôi quyết định ra quán đánh thêm một chiếc chìa khóa nữa, bỏ chiếc hòm cùng một chiếc chìa khóa vào trong chiếc VaLy và gửi ngược lại nó cho bạn.
Và kể từ lúc này chúng ta sẽ thông điệp với nhau bằng chiếc Hòm.
Oki, bây h thì đảm bảo là Tôi và bạn có thể trao đổi thông tin với nhau an toàn rồi.
Cứ tự nhiên gửi tiền cho mình nhé!!!
						
2. Cài đặt cấu hình
Mặc định dịch vụ OpenSSH đã được cài đặt trong quá trình cài đặt hệ thống Linux
Các gói cài đặt cơ bản của OpenSSH có dạng:
•	openssh-[phiên bản]
•	openssh-server-[phiên bản]
Kiểm tra OpenSSH đã được cài đặt trên hệ thống:
# rpm -qa | grep ssh
Nếu hệ thống chưa có dịch vụ OpenSSH, ta có thể cài đặt dịch vụ này theo một trong hai cách sau:
•	Cài đặt qua gói (pakages) dùng lệnh rpm
# rpm –ivh openssh-[phiên bản].rpm openssh-server-[phiên bản].rpm
•	Cài đặt qua mạng dùng lệnh yum
# yum –y install ssh
2.1 Các files cấu hình cơ bản của dịch vụ OpenSSH

Tất cả các tập tin cấu hình của ssh đều nằm trong thư mục /etc/ssh. Ta sẽ khảo sát sơ lược một số file trong thư mục ssh này:
•	moduli: Chứa một nhóm Diffie-Hellman được sử dụng cho việc trao đổi khóa Diffie-Hellman, nó thực sự quan trọng để xây dựng một lớp bảo mật ở tầng vận chuyển dữ liệu. Khi các khóa được trao đổi với nhau bắt đầu ở một phiên kết nối SSH, một share secret value được tạo ra và không thể xác định bởi một trong hai bên kết nối, giá trị này sau đó sẽ được dùng để cung cấp chứng thực cho host.
•	ssh_config: file cấu hình mặc định cho SSH client của hệ thống.
•	sshd_config: File cấu hình cho sshd deamon.
•	ssh_host_dsa_key: DSA private key được sử dụng với sshd deamon.
•	ssh_host_dsa_key.pub: DSA public key được sử dụng bởi sshd deamon.
•	ssh_host_key: RSA private key được sử dụng bởi sshd deamon cho phiên bản 1 của giao thức SSH.
•	ssh_host_key.pub: RSA public key được sử dụng bởi sshd deamon cho phiên bản 1 của giao thức SSH.
•	ssh_host_rsa_key: RSA private key được sử dụng bởi sshd deamon cho phiên bản 2 của giao thức SSH.
•	ssh_host_rsa_key.pub: RSA public key được sử dụng bởi sshd deamon cho phiên bản 2 của giao thức SSH.
2.2	Cấu hình OpenSSH chứng thực bằng tài khoản hệ thống
Các lựa chọn chính trong file /etc/ssh/sshd_config:
•	Chấp nhận cho tài khoản người dùng root đăng nhập:
PermitRootLogin yes
•	Không chấp nhận (no) hoặc chấp nhận (yes) tài khoản có mật khẩu rỗng:
PermitEmptyPasswords no
•	Yêu cầu phải nhập mật khẩu khi đăng nhập:
PasswordAuthentication yes
•	Cấm người dùng truy cập:
DenyUsers user1 user2 user3
•	Cấm nhóm người dùng truy cập:
DenyGroups group1 group2
•	Cho phép người dùng truy cập:
AllowUsers user1 user2
•	Cho phép nhóm người dùng truy cập:
AllowGroups group1 group2
Sửa file /etc/ssh/sshd_config và thay đổi các lựa chọn như sau:
[root@localhost ~]# vi /etc/ssh/sshd_config
PermitRootLogin yes
PermitEmptyPasswords no
PasswordAuthentication yes
Sau đó khởi động lại dịch vụ OpenSSH:
[root@localhost ~]# /etc/rc.d/init.d/sshd restart
Stopping sshd: [ OK ]
Starting sshd: [ OK ]
3. DEMO sử dụng giao thức ssh 
Thông tin về ip máy chủ
 
Trong máy chạy hệ điều hành Windows ta sử dụng phềm Putty để tạo ssh đến một máy khác.




 
Nắm quyền kiểm soát thiết bị
 


Kết nối của bạn đã được kết nối một cách an toàn, mọi thông tin đã được mã hóa.
 










3. Chứng thực OpenSSH qua key không hỏi mật khẩu
Khác với chứng thực bằng mật khẩu, ở đây ta sẽ cấu hình SSH Server cho phép chứng thực người dùng thông qua khóa.
Ta sẽ tạo ra cặp khóa Public key & Private key bằng thuật toán RSA hoặc DSA.
•	Public key: Sử dụng cho Server
•	Private key: Sử dụng cho Client
Thuật toán này hổ trợ cặp khóa tạo ra cho độ dài max là 2048 bit
3.1Trên client
Bước 1:Tạo cặp khóa:
Chạy lệnh sau:
[root@localhost ~]# ssh-keygen -t rsa
(hoặc ssh-keygen -t dsa)
dùng đường dẫn mặc định và enter khi được hỏi password
Generating public/private rsa key pair.
Enter file in which to save the key (/home/user/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/user/.ssh/id_rsa.
Your public key has been saved in /home/user/.ssh/id_rsa.pub.
The key fingerprint is:
2b:92:ad:e1:5c:65:80:96:7b:d1:cb:4a:a4:4a:37:29 user@client.home.lan
Bước 2: Cấu hình ssh client sử dụng cặp khóa vừa tạo
Để bảo vệ tệp chứa cặp khóa id_rsa, ta nên chuyển vị trí của nó, vd. Chuyển sang /home/myfile/id_rsa.
Đồng thời phải thay đổi luôn đường dẫn của chúng (IdentityFile /myfile/id_rsa) trong file /etc/ssh/ssh_config.
Bước 3 :Đưa public pubkey của client lên server
Để làm được việc chứng thực không cần password, ta cần cung cấp cho server public_key của client, và phải được ghi vào trong file ~/.ssh/authorized_keys (được cấu hình trongsshd_config)
	Cách 1: dùng lệnh:
#ssh-copy.–id.-i /home/user/.ssh/id_rsa.pub usersvr@server.home.lan
	Cách 2: dùng lệnh:
# ssh usersvr@server.home.lan cat < /home/user/.ssh/id_rsa.pub ">" /home/usersvr/.ssh/authorized_keys
   Bước 4:  Kích hoạt chức năng chứng thực bằng key trên server, chỉnh sửa file /etc/ssh/sshd_config, thêm 2 dòng sau:
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
Khởi động lại dịch vụ sshd:
/etc/init.d/sshd restart
Bước 5: Kiểm tra kết quả
Tiến hành kết nối bằng lệnh:
ssh usersvr@server.home.lan
kết quả:
[root@localhost ~]# ssh usersvr@server.home.lan
Last login: Sun Jun 21 00:31:50 2009 from client.home.lan
[root@localhost ~]#


ỨNG DỰNG CỦA SSH &TELNET
SSH có thể được coi như thế hệ phát triển sau của TELNET. Hiện nay, cả SSH và TELNET vẫn được sử dụng rộng rãi trong các hệ thông điều khiển.
TELNET được sử dụng trong các hệ thống điều khiển không đòi hỏi tính bảo mật cao, còn ngược lại SSH được ưu tiên lựa chọn trong các hệ thông yêu cầu tính bảo mật như an ninh, giám sát....
-SSH được sử dụng như phương án sự phòng trong trường hợp các hệ thông điều khiển....
-SSH,TELNET được cài đặt trong các máy chủ như một phương án bị hỏng thiết bị đầu vào, các thiết bị hệ thống điều khiển...
-Một trong những ứng dụng nổi tiếng có thể kể đến như teamviewer, Droidmote, Chrome Remote Desktop....

