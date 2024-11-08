
# UPDATE REPO DEBIAN
<pre><code>apt update -y && apt upgrade -y && apt dist-upgrade -y && reboot</code></pre>

# UPDATE REPO UBUNTU
<pre><code>apt update && apt upgrade -y && update-grub && sleep 2 && reboot</pre></code>

# // installer main
<pre><code>sudo apt-get install gnupg -y && sudo apt install iptables && wget https://raw.githubusercontent.com/shadowstsc/registr/main/install.sh && chmod +x install.sh && ./install.sh</pre></code>