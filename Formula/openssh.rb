class Openssh < Formula
  desc "OpenBSD freely-licensed SSH connectivity tools"
  homepage "https://www.openssh.com/"
  url "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.9p1.tar.gz"
  mirror "https://mirror.vdms.io/pub/OpenBSD/OpenSSH/portable/openssh-7.9p1.tar.gz"
  version "7.9p1"
  sha256 "6b4b3ba2253d84ed3771c8050728d597c91cfce898713beb7b64a305b6f11aad"

  # Please don't resubmit the keychain patch option. It will never be accepted.
  # https://github.com/Homebrew/homebrew-dupes/pull/482#issuecomment-118994372

  depends_on "autoconf" => :build
  depends_on "pkg-config" => :build
#  depends_on "ldns"
  depends_on "openssl@1.1"
  plist_options :startup => true

  resource "com.openssh.sshd.sb" do
    url "https://opensource.apple.com/source/OpenSSH/OpenSSH-209.50.1/com.openssh.sshd.sb"
    sha256 "a273f86360ea5da3910cfa4c118be931d10904267605cdd4b2055ced3a829774"
  end

  # Both these patches are applied by Apple.
  patch do
    url "https://raw.githubusercontent.com/Homebrew/patches/1860b0a74/openssh/patch-sandbox-darwin.c-apple-sandbox-named-external.diff"
    sha256 "d886b98f99fd27e3157b02b5b57f3fb49f43fd33806195970d4567f12be66e71"
  end

  patch do
    url "https://raw.githubusercontent.com/Homebrew/patches/d8b2d8c2/openssh/patch-sshd.c-apple-sandbox-named-external.diff"
    sha256 "3505c58bf1e584c8af92d916fe5f3f1899a6b15cc64a00ddece1dc0874b2f78f"
  end

  patch do
    url "https://github.com/oxeva/homebrew-taps/raw/master/patches/0001-Apply-PKCS11-ECDSA-and-PKCS11-URI-patches-from-Fedor.patch"
    sha256 "90706e35c7722924dcfb4d1a50fc0cf8ae14e7970e870096306714c4c34c22d5"
  end

  patch do
    url "https://github.com/oxeva/homebrew-taps/raw/master/patches/0002-Add-support-to-load-additional-certificates.patch"
    sha256 "ae59ac22baeb4cc0965334173ca8f92ee13111033976d99cf15b284b7b402d98"
  end

  def install
    ENV.append "CPPFLAGS", "-D__APPLE_SANDBOX_NAMED_EXTERNAL__"

    # Ensure sandbox profile prefix is correct.
    # We introduce this issue with patching, it's not an upstream bug.
    inreplace "sandbox-darwin.c", "@PREFIX@/share/openssh", etc/"ssh"

    args = %W[
      --prefix=#{prefix}
      --sysconfdir=#{etc}/ssh
      --with-libedit
      --with-kerberos5
      --with-pam
      --with-ssl-dir=#{Formula["openssl@1.1"].opt_prefix}
      --with-default-pkcs11-provider=/usr/local/lib/opensc-pkcs11.so
    ]

    system "autoreconf"
    system "./configure", *args
    system "make"
    ENV.deparallelize
    system "make", "install"

    # This was removed by upstream with very little announcement and has
    # potential to break scripts, so recreate it for now.
    # Debian have done the same thing.
    bin.install_symlink bin/"ssh" => "slogin"

    buildpath.install resource("com.openssh.sshd.sb")
    (etc/"ssh").install "com.openssh.sshd.sb" => "org.openssh.sshd.sb"
  end

  def plist; <<~EOS
    <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
                <key>Label</key>
                <string>#{plist_name}</string>
                <key>ProgramArguments</key>
                <array>
                        <string>/usr/local/bin/ssh-agent</string>
                        <string>-D</string>
                        <string>-a</string>
                        <string>#{ENV["HOME"]}/.ssh-agent.sock</string>
                </array>
                <key>RunAtLoad</key>
                <true/>
                <key>KeepAlive</key>
	              <dict>
                        <key>SuccessfulExit</key>
                        <false/>
                </dict>
                <key>Sockets</key>
                <dict>
                        <key>Listener</key>
                        <dict>
                          <key>SockPathName</key>
                          <string>#{ENV["HOME"]}/.ssh-agent.sock</string>
                        </dict>
                </dict>
                <key>EnableTransactions</key>
                <true/>
        </dict>
        </plist>
    EOS
  end

  test do
    assert_match "OpenSSH_", shell_output("#{bin}/ssh -V 2>&1")

    begin
      pid = fork { exec sbin/"sshd", "-D", "-p", "8022" }
      sleep 2
      assert_match "sshd", shell_output("lsof -i :8022")
    ensure
      Process.kill(9, pid)
      Process.wait(pid)
    end
  end
end
