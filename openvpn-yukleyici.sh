#!/bin/bash
# Debian, Ubuntu, CentOS, Amazon Linux 2, Fedora ve Arch Linux için OpenVPN yükleyici

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		# shellcheck disable=SC1091
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 8 ]]; then
				echo "⚠️ Debian versiyonunuz desteklenmiyor ⚠️"
				echo ""
				echo "Ancak, Debian 8 veya kararsız/test sürümü kullanıyorsanız, riski tarafınıza olmak üzere devam edebilirsiniz."
				echo ""
				until [[ $CONTINUE =~ (e|h) ]]; do
					read -rp "Devam et? [e/h]: " -e CONTINUE
				done
				if [[ $CONTINUE == "h" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ Ubuntu versiyonunuz desteklenmiyor ⚠️"
				echo ""
				echo "Ancak, Ubuntu 16.04 veya kararsız/test sürümü kullanıyorsanız, riski tarafınıza olmak üzere devam edebilirsiniz."
				echo ""
				until [[ $CONTINUE =~ (e|h) ]]; do
					read -rp "Devam et? [e/h]: " -e CONTINUE
				done
				if [[ $CONTINUE == "h" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/system-release ]]; then
		# shellcheck disable=SC1091
		source /etc/os-release
		if [[ $ID == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" ]]; then
			OS="centos"
			if [[ ! $VERSION_ID =~ (7|8) ]]; then
				echo "⚠️ CentOS versiyonunuz desteklenmiyor ⚠️"
				echo ""
				echo "Bu betik yalnızca CentOS 7 versiyonunu desteklemektedir."
				echo ""
				exit 1
			fi
		fi
		if [[ $ID == "amzn" ]]; then
			OS="amzn"
			if [[ $VERSION_ID != "2" ]]; then
				echo "⚠️ Amazon Linux versiyonunuz desteklenmiyor ⚠️"
				echo ""
				echo "Bu betik yalnızca Amazon Linux 2 versiyonunu desteklemektedir."
				echo ""
				exit 1
			fi
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Bu betiği Debian, Ubuntu, Fedora, CentOS, Amazon Linux 2 veya Arch Linux sisteminde çalıştırmıyorsunuz gibi görünüyor?"
    echo "Lütfen betiği Debian, Ubuntu, Fedora, CentOS, Amazon Linux 2 veya Arch Linux sisteminde çalıştırın 🤐"
		exit 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo "Üzgünüz, ancak bu betiği root ya da sudo yetkilerine sahip bir kullanıcı olarak çalıştırmanız gerekiyor!"
		exit 1
	fi
	if ! tunAvailable; then
		echo "Sunucunuzda TUN mevcut değil!"
		exit 1
	fi
	checkOS
}

function installUnbound() {
	# Unbound yüklenmemişse yükle
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get install -y unbound

			# Yapılandırma
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf

		elif [[ $OS =~ (centos|amzn) ]]; then
			yum install -y unbound

			# Yapılandırma
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "fedora" ]]; then
			dnf install -y unbound

			# Yapılandırma
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "arch" ]]; then
			pacman -Syu --noconfirm unbound

			# Root sunucu listesini al
			curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache

			if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
				mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
			fi

			echo 'server:
	use-syslog: yes
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes' >/etc/unbound/unbound.conf
		fi

		# IPv6 DNS
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
		fi


		if [[ ! $OS =~ (fedora|centos|amzn) ]]; then
			# DNS Rebind çözümü
			echo "private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
		fi
	else # Unbound zaten yüklenmiş
		echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf

		# OpenVPN subnetine Unbound ekle
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
		fi
	fi

	systemctl enable unbound
	systemctl restart unbound
}

function installQuestions() {
	echo "- OpenVPN yükleyiciye hoş geldiniz!"
	echo "- Destek almak için: https://www.muhyal.com/t/220 🤔"
	echo "- Kurulum sonrası nasıl bağlantı sağlayacağınızı öğrenmek için: https://www.muhyal.com/t/220/2 🙄"
	echo "- Kurulum sırasında size bazı sorular sorulacaktır. Lütfen bu soruları dikkatlice okuyarak yanıtlayınız 🧐"
  echo "- (e) yanıtı (Evet ✅  ) demektir. (h) yanıtı (Hayır ❌  ) demektir."
	echo "- MUHYAL'a güveniyorsanız ve hiç sorularla uğraşmak istemiyorsanız direkt Enter tuşu ile kurulumu tamamlayabilirsiniz 🤓"
	echo "
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%*..........%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%..........................%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%...................................%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%.........................................%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%........%%%%%%................................%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%.........%%%%%%%%%.............................%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%...........%%%%%%%%%%%%........................%%%%%%%%%%%%%%%%%....%%%%%
%%%%%%............%%%%%%%%%%%%%%...................%%%%%%%%%%%%%%%%%%%%....%%%%%
%%%%%.............%%%%%%%%%%%%%%%%%..............%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%..............%%%%%%%%%%%%%%%%%%%..........%%%%%%%%%%%%%%%%........%%%%%%%%%
%%%%..............%%%%%%%%%%%%%%%%%%%%%.....%%%%%%%%%%%%%%%%%%%........%%%%%%%%%
%%%...............%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%........%%%%%%%%%
%%%...............%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%(.....(%%
%%%...............%%%%%%%%%%%...%%%%%%%%%%%%%%%%%%%%..%%%%%%%%%%%%%%%%%.......%%
%%%%..............%%%%%%%%%%%.....%%%%%%%%%%%%%%%%....%%%%%%%%%%%%%%%%%.......%%
%%%%..............%%%%%%%%%%%.......%%%%%%%%%%%#......%%%%%%%%........%%%%%%%%%%
%%%%%.............%%%%%%%%%%%.........%%%%%%%.........%%%%%%%..........%%%%%%%%%
%%%%%%............%%%%%%%%%%%...........#%%...........%%%%%%%..........%%%%%%%%%
%%%%%%%...........,%%%%%%%%%%.........................%%%%%%%..........%%%%%%%%%
%%%%%%%%%..........%%%%%%%%%%.........................%%%%%%%..........%%%%%%%%%
%%%%%%%%%%%..........%%%%%%%%.........................%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%............(%%%.........................%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%,..................................%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%..........................%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.........*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
"
	# IPv4 adresini algıla ve kullanıcı yerine tanımla
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	if [[ -z $IP ]]; then
		# Genele açık IPv6 adresini algıla
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "Sunucu genele açık IP adresi: " -e -i "$IP" IP
	fi
	# Eğer $IP özel ise sunucu NAT arkasında mı kontrol et
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "Bu sunucu NAT arkasında görünüyor. Genel IPv4 adresi veya ana bilgisayar adı nedir?"
		echo "VPN istemcilerinin sunucuya bağlanması için bu gerekmektedir."
		until [[ $ENDPOINT != "" ]]; do
			read -rp "Genel IPv4 adresi veya ana bilgisayar adınız: " -e ENDPOINT
		done
	fi

	echo ""
	echo "IPv6 bağlantısı varlığı kontrol ediliyor..."
	echo ""
	# "ping6" ve "ping -6" kullanımı işletim sistemi dağıtımuna göre değişmektedir
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "Sunucunuzda IPv6 bağlantısı var gibi görünüyor."
		SUGGESTION="e"
	else
		echo "Sunucunuzda IPv6 bağlantısı yok gibi görünüyor."
		SUGGESTION="h"
	fi
	echo ""
	# Kullanıcının, kullanılabilirliğine bakılmaksızın IPv6'yı etkinleştirmek isteyip istemediklerini sor
	until [[ $IPV6_SUPPORT =~ (e|h) ]]; do
		read -rp "IPv6 desteğini etkinleştirmek istiyor musunuz (NAT)? [e/h]: " -e -i $SUGGESTION IPV6_SUPPORT
	done
	echo ""
	echo "OpenVPN'in hangi bağlantı noktasını dinlemesini istersiniz?"
	echo "   1) Varsayılan (Önerilen): 1194"
	echo "   2) Özel"
	echo "   3) Rastgele oluştur [49152 ile 65535 arası]"
	until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "Bağlantı noktası seçiniz [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "Özel bağlantı noktası [1 ile 65535 arası]: " -e -i 1194 PORT
		done
		;;
	3)
		# Belirlenen özel aralıkta rastgele bağlantı noktası oluştur
		PORT=$(shuf -i49152-65535 -n1)
		echo "Rastgele oluşturulan bağlantı noktası: $PORT"
		;;
	esac
	echo ""
	echo "OpenVPN'in hangi protokolü kullanmasını istiyorsunuz?"
	echo "UDP her zaman daha hızlıdır. Kullanılabilir ve yapılandırılmış durumda olmadığı sürece TCP kullanmamalısınız."
	echo "   1) UDP (Önerilen)"
	echo "   2) TCP"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "Protokol seçimi [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "VPN sunucunuzda hangi DNS sağlayacısını kullanmak istiyorsunuz?"
	echo "   1) Mevcut sistem yapılandırması (/etc/resolv.conf yapılandırmasından)"
	echo "   2) Barındırılan DNS sağlayıcısı (Unbound)"
	echo "   3) AdGuard DNS (Önerilen, reklamlarıda engeller 😉)"
	echo "   4) Quad9"
	echo "   5) Quad9 sansürsüz"
	echo "   6) FDN (Fransa)"
	echo "   7) DNS.WATCH (Almanya)"
	echo "   8) OpenDNS"
	echo "   9) Google"
	echo "   10) Yandex (Rusya)"
	echo "   11) Cloudflare"
	echo "   12) NextDNS"
	echo "   13) Özel"
	until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 13 ]; do
		read -rp "DNS [1-12]: " -e -i 3 DNS
		if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
			echo ""
			echo "Unbound zaten yüklenmiş."
			echo "Betiğin OpenVPN istemcilerinizin kullanması için bu özelliği yapılandırmasına izin verebilirsiniz."
			echo "OpenVPN alt ağı için /etc/unbound/unbound.conf dosyasına ikinci bir sunucu eklenecek."
			echo "Geçerli yapılandırmada başka hiçbir değişiklik yapılmayacaktır."
			echo ""

			until [[ $CONTINUE =~ (e|h) ]]; do
				read -rp "Unbound'a yapılandırma değişiklikleri uygulansın mı? [e/h]: " -e CONTINUE
			done
			if [[ $CONTINUE == "h" ]]; then
				# Döngüyü burada kır ve temizlik yap
				unset DNS
				unset CONTINUE
			fi
		elif [[ $DNS == "13" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Birinci DNS adresi: " -e DNS1
			done
			until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "İkinci DNS adresi (opsiyoneldir): " -e DNS2
				if [[ $DNS2 == "" ]]; then
					break
				fi
			done
		fi
	done
	echo ""
	echo "Sıkıştırma kullanmak istiyor musunuz? VORACLE saldırısı bundan faydalandığı için ÖNERİLMEZ!"
	until [[ $COMPRESSION_ENABLED =~ (e|h) ]]; do
		read -rp"Sıkıştırma aktif edilsin mi? [e/h]: " -e -i h COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "e" ]]; then
		echo "Hangi sıkıştırma algoritmasını kullanmak istediğinizi seçin: (verimliliklerine göre sıralı)"
		echo "   1) LZ4-v2"
		echo "   2) LZ4"
		echo "   3) LZ0"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp"Sıkıştırma algoritması [1-3]: " -e -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
		1)
			COMPRESSION_ALG="lz4-v2"
			;;
		2)
			COMPRESSION_ALG="lz4"
			;;
		3)
			COMPRESSION_ALG="lzo"
			;;
		esac
	fi
	echo ""
	echo "Şifreleme ayarlarını özelleştirmek istiyor musunuz?"
	echo "Ne yaptığınızı bilmiyorsanız, komut dosyası tarafından sağlanan varsayılan parametrelere bağlı kalmalısınız."
	echo "Ne seçerseniz seçin, komut dosyasında sunulan tüm seçeneklerin güvenli olduğunu unutmayın (OpenVPN'in varsayılanlarının aksine)."
	echo "Detaylı bilgi için: https://www.muhyal.com/t/220/2"
	echo ""
	until [[ $CUSTOMIZE_ENC =~ (e|h) ]]; do
		read -rp "Şifreleme ayarlarını özelleştirmek istiyor musunuz? [e/h]: " -e -i h CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "h" ]]; then
		# Varsayılan olarak, akıllı ve hızlı parametreleri kullan
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	else
		echo ""
		echo "Veri kanalı için kullanmak istediğiniz şifreleme türünü seçin:"
		echo "   1) AES-128-GCM (Önerilen)"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
			read -rp "Şifreleme türü seçiniz [1-6]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		esac
		echo ""
		echo "Ne tür bir sertifika kullanmak istediğinizi seçin:"
		echo "   1) ECDSA (Önerilen)"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp"Sertifika türü seçiniz [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
		1)
			echo ""
			echo "Sertifika anahtarınız için hangi yönelim kullanılsın?"
			echo "   1) prime256v1 (Önerilen)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp"Yönelim seçiniz [1-3]: " -e -i 1 CERT_CURVE_CHOICE
			done
			case $CERT_CURVE_CHOICE in
			1)
				CERT_CURVE="prime256v1"
				;;
			2)
				CERT_CURVE="secp384r1"
				;;
			3)
				CERT_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "Sertifikanın RSA anahtarı için hangi boyutu kullanmak istiyorsunuz?"
			echo "   1) 2048 bits (Önerilen)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits"
			until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "RSA anahtarı boyutu seçiniz [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
			done
			case $RSA_KEY_SIZE_CHOICE in
			1)
				RSA_KEY_SIZE="2048"
				;;
			2)
				RSA_KEY_SIZE="3072"
				;;
			3)
				RSA_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		echo "Kontrol kanalı için kullanmak istediğiniz şifrelemeyi seçin:"
		case $CERT_TYPE in
		1)
			echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (Önerilen)"
			echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Kontrol kanalı şifrelemesini seçiniz [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		2)
			echo "   1) ECDHE-RSA-AES-128-GCM-SHA256 (Önerilen)"
			echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Kontrol kanalı şifrelemesini seçiniz [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		esac
		echo ""
		echo "Ne tür bir Diffie-Hellman anahtarı kullanmak istediğinizi seçin:"
		echo "   1) ECDH (Önerilen)"
		echo "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
			read -rp"Diffie-Hellman anahtar türünü seçiniz [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
		1)
			echo ""
			echo "ECDH anahtarı için hangi şifrelemeyi kullanmak istiyorsunuz?"
			echo "   1) prime256v1 (Önerilen)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
				read -rp"ECDH anahtarı şifrelemesini seçiniz [1-3]: " -e -i 1 DH_CURVE_CHOICE
			done
			case $DH_CURVE_CHOICE in
			1)
				DH_CURVE="prime256v1"
				;;
			2)
				DH_CURVE="secp384r1"
				;;
			3)
				DH_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "Hangi boyutta Diffie-Hellman anahtarını kullanmak istediğinizi seçin:"
			echo "   1) 2048 bits (Önerilen, 5-10 dakika arası sürer)"
			echo "   2) 3072 bits (Oluşturulması çok uzun sürecektir)"
			echo "   3) 4096 bits (Oluşturulması çok daha uzun sürecektir)"
			until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "Diffie-Hellman anahtarı bouyutunu seçiniz [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
			done
			case $DH_KEY_SIZE_CHOICE in
			1)
				DH_KEY_SIZE="2048"
				;;
			2)
				DH_KEY_SIZE="3072"
				;;
			3)
				DH_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		# "Kimlik doğrulaması" seçenekleri AEAD şifrelemelerinde farklı davranır
		if [[ $CIPHER =~ CBC$ ]]; then
			echo "Özet algoritması, veri kanalı paketlerini ve tls-auth paketlerini kontrol kanalından doğrular."
		elif [[ $CIPHER =~ GCM$ ]]; then
			echo "Özet algoritması, kontrol kanalından tls-auth paketlerinin kimliğini doğrular."
		fi
		echo "HMAC için hangi özet algoritmasını kullanmak istiyorsunuz?"
		echo "   1) SHA-256 (Önerilen)"
		echo "   2) SHA-384"
		echo "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "Özet algoritmasını seçiniz [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
		1)
			HMAC_ALG="SHA256"
			;;
		2)
			HMAC_ALG="SHA384"
			;;
		3)
			HMAC_ALG="SHA512"
			;;
		esac
		echo ""
		echo "tls-auth ve tls-crypt ile kontrol kanalına ek bir güvenlik katmanı ekleyebilirsiniz."
		echo "tls-auth paketleri doğrularken, tls-crypt bunları doğrular ve şifreler."
		echo "   1) tls-crypt (Önerilen)"
		echo "   2) tls-auth"
		until [[ $TLS_SIG =~ [1-2] ]]; do
			read -rp "Kontrol kanalı ek güvenlik mekanizması seçiniz [1-2]: " -e -i 1 TLS_SIG
		done
	fi
	echo ""
	echo "Tamamdır 👍 Tüm sorularımız için gereken yanıtlarımızı aldık. Artık OpenVPN sunucunuzu kurmaya hazırız ✅"
	echo "Kurulumun sonunda sunucunuza bağlanmak için kullanacağınız istemci ya da istemcilerinizi oluşturabileceksiniz."
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Devam etmek için herhangi bir tuşa basın..."
	fi
}
function installOpenVPN() {
	if [[ $AUTO_INSTALL == "e" ]]; then
		# Hiçbir soru sorulmayacak şekilde varsayılan seçenekleri belirle
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		IPV6_SUPPORT=${IPV6_SUPPORT:-n}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-1}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}
		# Sunucu NAT'ın arkasında ise, herkese açık olarak erişilebilen IPv4/IPv6'yı varsayılan olarak kullan
		if [[ $IPV6_SUPPORT == "e" ]]; then
			PUBLIC_IP=$(curl https://ifconfig.co)
		else
			PUBLIC_IP=$(curl -4 https://ifconfig.co)
		fi
		ENDPOINT=${ENDPOINT:-$PUBLIC_IP}
	fi
	# Önce kurulum sorularını çalıştır ve otomatik kurulum yapılması ihtimaline karşı diğer değişkenleri ayarla
	installQuestions
	# Varsayılan ağ yollarını algıla
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'e' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi
	# $NIC openvpn-kurallari-kaldir.sh komut dosyası için boş olamaz
	if [[ -z $NIC ]]; then
		echo
		echo "Genel ağ arayüzü algılanamıyor."
		echo "MASQUERADE kurulumu gerekiyor."
		until [[ $CONTINUE =~ (e|h) ]]; do
			read -rp "Devam edilsin mi? [e/h]: " -e CONTINUE
		done
		if [[ $CONTINUE == "h" ]]; then
			exit 1
		fi
	fi
	# OpenVPN henüz kurulmadıysa kur
	if [[ ! -e /etc/openvpn/server.conf ]]; then
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get update
			apt-get -y install ca-certificates gnupg
			# En son sürümü almak için OpenVPN deposunu ekle
			if [[ $VERSION_ID == "8" ]]; then
				echo "deb http://build.openvpn.net/debian/openvpn/stable jessie main" >/etc/apt/sources.list.d/openvpn.list
				wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
				apt-get update
			fi
			if [[ $VERSION_ID == "16.04" ]]; then
				echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
				wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
				apt-get update
			fi
			# Ubuntu 16.04 ve Debian 8 üzeri versiyonlar resmi yazılım depolarında OpenVPN 2.4'ü barındırır
			apt-get install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'centos' ]]; then
			yum install -y epel-release
			yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
		elif [[ $OS == 'amzn' ]]; then
			amazon-linux-extras install -y epel
			yum install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'fedora' ]]; then
			dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils
		elif [[ $OS == 'arch' ]]; then
			# Gerekli bağımlılıkları yükle ve sistemi yükselt
			pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
		fi
		# easy-rsa paketinin eski bir sürümü varsayılan olarak bazı openvpn paketlerinde zaten mevcut
		if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
	fi
	# Sunucuda nogroup ya da nobody kontrolü yap
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi
	# Zaten kurulmamışsa easy-rsa paketinin en son sürümünü kaynağından yükle
	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		local version="3.0.7"
		wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz
		cd /etc/openvpn/easy-rsa/ || return
		case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac
		# CN ve sunucu adı için rastgele 16 karakterli bir alfasayısal tanımlayıcı oluştur
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED
		echo "set_var EASYRSA_REQ_CN $SERVER_CN" >>vars
		# PKI oluştur, CA, DH parametrelerini ve sunucu sertifikasını ayarla
		./easyrsa init-pki
		# easy-rsa 3.0.7 hatasını gidermek için geçici çözüm
		# https://github.com/OpenVPN/easy-rsa/issues/261
		sed -i 's/^RANDFILE/#RANDFILE/g' pki/openssl-easyrsa.cnf
		./easyrsa --batch build-ca nopass
		if [[ $DH_TYPE == "2" ]]; then
			# ECDH anahtarları anlık olarak oluşturulur
			# Bu nedenle bunları önceden oluşturmamız gerekmiyor
			openssl dhparam -out dh.pem $DH_KEY_SIZE
		fi
		./easyrsa build-server-full "$SERVER_NAME" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
		case $TLS_SIG in
		1)
			# tls-crypt anahtarı oluştur
			openvpn --genkey --secret /etc/openvpn/tls-crypt.key
			;;
		2)
			# tls-auth anahtarı oluştur
			openvpn --genkey --secret /etc/openvpn/tls-auth.key
			;;
		esac
	else
		# easy-rsa zaten kurulu ise oluşturulmuş SERVER_NAME kısmını yakala
		# İstemci yapılandırmaları için
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi
	# Oluşturulan tüm dosyaları taşı
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	if [[ $DH_TYPE == "2" ]]; then
		cp dh.pem /etc/openvpn
	fi
	# Sertifika iptal listesini root olmayanlar için okunabilir hale getir
	chmod 644 /etc/openvpn/crl.pem
	# server.conf oluştur
	echo "port $PORT" >/etc/openvpn/server.conf
	if [[ $IPV6_SUPPORT == 'h' ]]; then
		echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
	elif [[ $IPV6_SUPPORT == 'e' ]]; then
		echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
	fi
	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf
	# DNS sağlayıcıları
	case $DNS in
	1) # Mevcut sistem sağlayıcıları
		# Doğru resolv.conf dosyasını bul
		# Bı kısım systemd-resolved ile çalışan sunucular için gereklidir
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Sağlayıcıları resolv.conf dosyasından edin ve OpenVPN için kullan
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# IPv4 ya da IPv6 etkinse, IPv4/IPv6 önemli değil
			if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'e' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
			fi
		done
		;;
	2) # Unbound
		echo 'push "dhcp-option DNS 10.8.0.1"' >>/etc/openvpn/server.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'push "dhcp-option DNS fd42:42:42:42::1"' >>/etc/openvpn/server.conf
		fi
		;;
	3) # AdGuard DNS
		echo 'push "dhcp-option DNS 176.103.130.130"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 176.103.130.131"' >>/etc/openvpn/server.conf
		;;
	4) # Quad9
		echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server.conf
		;;
	5) # Quad9 sansürsüz
		echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server.conf
		;;
	6) # FDN
		echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server.conf
		;;
	7) # DNS.WATCH
		echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server.conf
		;;
	8) # OpenDNS
		echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
		;;
	9) # Google
		echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
		;;
	10) # Yandex
		echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server.conf
		;;
	11) # Cloudflare
		echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
		;;
	12) # NextDNS
		echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server.conf
		;;
	13) # Özel DNS
		echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server.conf
		if [[ $DNS2 != "" ]]; then
			echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server.conf
		fi
		;;
	esac
	echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf
	# Gerekirse IPv6 ağ ayarları
	if [[ $IPV6_SUPPORT == 'e' ]]; then
		echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >>/etc/openvpn/server.conf
	fi
	if [[ $COMPRESSION_ENABLED == "e" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server.conf
	fi
	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >>/etc/openvpn/server.conf
		echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
	elif [[ $DH_TYPE == "2" ]]; then
		echo "dh dh.pem" >>/etc/openvpn/server.conf
	fi
	case $TLS_SIG in
	1)
		echo "tls-crypt tls-crypt.key 0" >>/etc/openvpn/server.conf
		;;
	2)
		echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
		;;
	esac
	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server.conf
	# client-config-dir dizini oluştur
	mkdir -p /etc/openvpn/ccd
	# Günlük dizini oluştur
	mkdir -p /var/log/openvpn
	# Yönlendirmeyi etkinleştir
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/20-openvpn.conf
	if [[ $IPV6_SUPPORT == 'e' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/20-openvpn.conf
	fi
	# sysctl kurallarını uygula
	sysctl --system
	# SELinux etkinse ve özel bir bağlantı noktası seçilmişse buna burada ihtiyacımız var
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi
	# Yeniden başlat ve OpenVPN etkinleştir
	if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' ]]; then
		# Paket tarafından sağlanan hizmeti değiştirme
		cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service
		# OpenVZ'de OpenVPN hizmetini düzeltmek için geçici çözüm
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
		# /etc/openvpn/ komutunu kullanmaya devam etmek için başka bir geçici çözüm
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service
		# Fedora'da ilgili hizmet şifreleri zor kodlar. Şifreyi kendimiz yönetmek istediğimiz için onu ilgili hizmetten kaldır.
		if [[ $OS == "fedora" ]]; then
			sed -i 's|--cipher AES-256-GCM --ncp-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC:BF-CBC||' /etc/systemd/system/openvpn-server@.service
		fi
		systemctl daemon-reload
		systemctl enable openvpn-server@server
		systemctl restart openvpn-server@server
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		# Ubuntu 16.04 ise paketi OpenVPN deposundan kullan
		# Bu paket bir sysvinit hizmeti kullanır
		systemctl enable openvpn
		systemctl start openvpn
	else
		# Paket tarafından sağlanan hizmeti değiştirmeden devam et
		cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service
		# OpenVZ üzerinde OpenVPN hizmetini düzeltmek için geçici çözüm
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
		# /etc/openvpn/ komutunu kullanmaya devam etmek için başka bir geçici çözüm
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service
		systemctl daemon-reload
		systemctl enable openvpn@server
		systemctl restart openvpn@server
	fi
	if [[ $DNS == 2 ]]; then
		installUnbound
	fi
	# İki komut dosyasına iptables kuralları ekle
	mkdir -p /etc/iptables
	# Kural eklemek için komut dosyası
	echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/openvpn-kurallari-ekle.sh
	if [[ $IPV6_SUPPORT == 'e' ]]; then
		echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/openvpn-kurallari-ekle.sh
	fi
	# Kural kaldırmak için komut dosyası
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/openvpn-kurallari-kaldir.sh
	if [[ $IPV6_SUPPORT == 'e' ]]; then
		echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/openvpn-kurallari-kaldir.sh
	fi
	chmod +x /etc/iptables/openvpn-kurallari-ekle.sh
	chmod +x /etc/iptables/openvpn-kurallari-kaldir.sh
	# Bir systemd betiği aracılığıyla kuralları işle
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/etc/iptables/openvpn-kurallari-ekle.sh
ExecStop=/etc/iptables/openvpn-kurallari-kaldir.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service
	# Hizmeti etkinleştir ve kuralları uygula
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn
	# Sunucu NAT arkasındaysa, istemcilerin bağlanması için doğru IP adresini kullan
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi
	# kullaniciistemcisablonu.txt oluşturulduktan sonra daha sonra başka kullanıcılar eklemek için bir şablonumuz var
	echo "client" >/etc/openvpn/kullaniciistemcisablonu.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/kullaniciistemcisablonu.txt
		echo "explicit-exit-notify" >>/etc/openvpn/kullaniciistemcisablonu.txt
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >>/etc/openvpn/kullaniciistemcisablonu.txt
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Windows 10 DNS sızıntısını önle
verb 3" >>/etc/openvpn/kullaniciistemcisablonu.txt
	if [[ $COMPRESSION_ENABLED == "e" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/kullaniciistemcisablonu.txt
	fi
	# Özel kullaniciistemci.ovpn dosyası oluştur
	newClient
	echo "Daha fazla kullanıcı/istemci eklemek istiyorsanız, bu komut dosyasını dilediğiniz zaman çalıştırmanız yeterlidir 🤝"
}
function newClient() {
	echo ""
	echo "Kullanıcı/İstemci adı nedir?"
	echo "Yalnızca harfler kullanın, özel karakter kullanmayın."
	until [[ $CLIENT =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Kullanıcı/İstemci Adı: " -e CLIENT
	done
	echo ""
	echo "Yapılandırma dosyasını bir parola ile korumak istiyor musunuz?"
	echo "(Özel anahtar bir parolayla şifrelenecektir!)"
	echo "   1) Parolasız bir kullanıcı/istemci ekle (Önerilen)"
	echo "   2) Hayır, kullanıcıya/istemciye parola koruması ekle"
	until [[ $PASS =~ ^[1-2]$ ]]; do
		read -rp "Bir seçim yapmalısınız [1-2]: " -e -i 1 PASS
	done
	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		echo ""
		echo "Belirtilen kullanıcı/istemci CN zaten easy-rsa'da bulundu, lütfen başka bir ad seçin."
		exit
	else
		cd /etc/openvpn/easy-rsa/ || return
		case $PASS in
		1)
			./easyrsa build-client-full "$CLIENT" nopass
			;;
		2)
			echo "⚠️ Kullanıcı/İstemci bağlantı için aşağıdaki parolayı kullanmalıdır"
			./easyrsa build-client-full "$CLIENT"
			;;
		esac
		echo "$CLIENT kullanıcısı/istemcisi eklendi."
	fi
	# Kullanıcı/İstemci yapılandırmasının (.ovpn dosyasının) oluşturulacağı kullanıcı dizini
	if [ -e "/home/$CLIENT" ]; then # $1 bir kullanıcı adı ise
		homeDir="/home/$CLIENT"
	elif [ "${SUDO_USER}" ]; then # değilse, SUDO_USER kullan
		homeDir="/home/${SUDO_USER}"
	else # SUDO_USER değilse /root kullan
		homeDir="/root"
	fi
	# tls-auth veya tls-crypt kullanıp kullanmadığını belirle
	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
	fi
	# Özel kullaniciistemci.ovpn dosyası oluştur
	cp /etc/openvpn/kullaniciistemcisablonu.txt "$homeDir/$CLIENT.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"
		echo "<cert>"
		awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"
		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"
		case $TLS_SIG in
		1)
			echo "<tls-crypt>"
			cat /etc/openvpn/tls-crypt.key
			echo "</tls-crypt>"
			;;
		2)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"$homeDir/$CLIENT.ovpn"
	echo ""
	echo "🔒 İstemci yapılandırma dosyanız $homeDir/$CLIENT.ovpn dizininde oluşturuldu."
	echo "⬇️  .ovpn uzantılı istemci dosyanızı cihazınıza indirin ve OpenVPN programında içeri aktarın."
	echo "❔ Bu işlemleri nasıl yapacağınızı bilmiyorsanız: https://www.muhyal.com/t/220/2"
	exit 0
}
function revokeClient() {
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		echo ""
		echo "Şu an oluşturmuş olduğunuz bir kullanıcı/istemci bulunmuyor!"
		exit 1
	fi
	echo ""
	echo "İptal etmek istediğiniz mevcut istemci sertifikasını seçin"
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
		if [[ $CLIENTNUMBER == '1' ]]; then
			read -rp "Bir istemci seçiniz [1]: " CLIENTNUMBER
		else
			read -rp "Bir istemci seçiniz [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
		fi
	done
	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
	cd /etc/openvpn/easy-rsa/ || return
	./easyrsa --batch revoke "$CLIENT"
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	rm -f /etc/openvpn/crl.pem
	cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
	chmod 644 /etc/openvpn/crl.pem
	find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	rm -f "/root/$CLIENT.ovpn"
	sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt
	echo ""
	echo "$CLIENT kullanıcısı/istemcisi için sertifika kaldırıldı ✔️"
}
function removeUnbound() {
	# OpenVPN ile ilgili Unbound konfigürasyonunu kaldır
	sed -i '/include: \/etc\/unbound\/openvpn.conf/d' /etc/unbound/unbound.conf
	rm /etc/unbound/openvpn.conf
	until [[ $REMOVE_UNBOUND =~ (e|h) ]]; do
		echo ""
		echo "OpenVPN kurmadan önce zaten Unbound kullanıyorsanız, OpenVPN ile ilgili Unbound konfigürasyonunu betik kaldırdı."
		read -rp "Unbound'u tamamen kaldırmak istiyor musunuz? [e/h]: " -e REMOVE_UNBOUND
	done
	if [[ $REMOVE_UNBOUND == 'e' ]]; then
		# Unbound'u durdur
		systemctl stop unbound
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get autoremove --purge -y unbound
		elif [[ $OS == 'arch' ]]; then
			pacman --noconfirm -R unbound
		elif [[ $OS =~ (centos|amzn) ]]; then
			yum remove -y unbound
		elif [[ $OS == 'fedora' ]]; then
			dnf remove -y unbound
		fi
		rm -rf /etc/unbound/
		echo ""
		echo "Unbound kaldırıldı!"
	else
		systemctl restart unbound
		echo ""
		echo "Unbound kaldıralamadı!"
	fi
}
function removeOpenVPN() {
	echo ""
	# shellcheck disable=SC2034
	read -rp "Cidden, OpenVPN sunucunuzdan tamamen kaldırılsın mı? [e/h]: " -e -i h REMOVE
	if [[ $REMOVE == 'e' ]]; then
		# Yapılandırmadan OpenVPN bağlantı noktasını al
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
		# OpenVPN durdur
		if [[ $OS =~ (fedora|arch|centos) ]]; then
			systemctl disable openvpn-server@server
			systemctl stop openvpn-server@server
			# Özelleştirilmiş hizmeti kaldır
			rm /etc/systemd/system/openvpn-server@.service
		elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
			systemctl disable openvpn
			systemctl stop openvpn
		else
			systemctl disable openvpn@server
			systemctl stop openvpn@server
			# Özelleştirilmiş hizmeti kaldır
			rm /etc/systemd/system/openvpn\@.service
		fi
		# Komut dosyasıyla ilgili iptables kurallarını kaldır
		systemctl stop iptables-openvpn
		# Temizlik zamanı
		systemctl disable iptables-openvpn
		rm /etc/systemd/system/iptables-openvpn.service
		systemctl daemon-reload
		rm /etc/iptables/openvpn-kurallari-ekle.sh
		rm /etc/iptables/openvpn-kurallari-kaldir.sh
		# SELinux
		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if [[ $PORT != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
				fi
			fi
		fi
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get autoremove --purge -y openvpn
			if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
				rm /etc/apt/sources.list.d/openvpn.list
				apt-get update
			fi
		elif [[ $OS == 'arch' ]]; then
			pacman --noconfirm -R openvpn
		elif [[ $OS =~ (centos|amzn) ]]; then
			yum remove -y openvpn
		elif [[ $OS == 'fedora' ]]; then
			dnf remove -y openvpn
		fi
		# Temizlik zamanı
		find /home/ -maxdepth 2 -name "*.ovpn" -delete
		find /root/ -maxdepth 1 -name "*.ovpn" -delete
		rm -rf /etc/openvpn
		rm -rf /usr/share/doc/openvpn*
		rm -f /etc/sysctl.d/20-openvpn.conf
		rm -rf /var/log/openvpn
		# Unbound
		if [[ -e /etc/unbound/openvpn.conf ]]; then
			removeUnbound
		fi
		echo ""
		echo "İsteğiniz üzerine OpenVPN sunucunuzdan kaldırıldı!"
	else
		echo ""
		echo "İsteğiniz üzerine OpenVPN kaldırma işlemi iptal edildi!"
	fi
}
function manageMenu() {
	echo "OpenVPN yükleyiciye hoş geldiniz!"
	echo "Destek ve detaylı bilgi için: https://www.muhyal.com/t/220/"
	echo ""
	echo "Görünüşe göre OpenVPN zaten kurulu."
	echo ""
	echo "Sizin için ne yapabilirim?"
	echo "   1) Yeni VPN kullanıcısı/istemcisi ekle"
	echo "   2) Bir VPN kullanıcısı/istemcisini kaldır"
	echo "   3) Sunucumdan OpenVPN'i kaldır"
	echo "   4) Çıkış yap"
	until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
		read -rp "Size nasıl yardımcı olabilirim? [1-4]: " MENU_OPTION
	done
	case $MENU_OPTION in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		removeOpenVPN
		;;
	4)
		exit 0
		;;
	esac
}
# root, TUN, OS kontrolü yap...
initialCheck
# OpenVPN'in kurulu olup olmadığını kontrol et
if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "e" ]]; then
	manageMenu
else
	installOpenVPN
fi
