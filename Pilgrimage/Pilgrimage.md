# Hack The Box Writeup - Pilgrimage (Easy)

![PilgrimageCard](/Pilgrimage/images/Pilgrimage.png)

As always, we start with a nmap scan. The output reveals that the machine has two ports open: 22 (ssh) and 80 (http).

![Nmap Scan](/Pilgrimage/images/nmap.png)

It also reveals that the http-title redirected to `http://pilgrimage.htb/`. So let's go ahead and put that in our `/etc/hosts`

![Domain](/Pilgrimage/images/domain.png)

After adding the domain, if we run the nmap scan again, it says that there is a `.git` repository.

![Nmap Scan](/Pilgrimage/images/nmap_1.png)

We can use the `git-dumper` tool to dump the source code.

![Git Dumper](/Pilgrimage/images/git_dumper.png)

After checking the files in the source code, the `index.php` file contains some useful information. The application is using the magick tool for image processing. The file also contains the location of the sqlite database.

![Index.php](/Pilgrimage/images/index.png)

The executable binary is also downloaded by the `git-dumper`. We can use the `exiftool` to find more information about the binary.

![Magick](/Pilgrimage/images/magick.png)

It is using magick version 12.63. After a quick internet search, we can find that there is Arbitrary File Read vulnerability in this version. There is a PoC that can be used to exploit this vulnerability <https://github.com/voidz0r/CVE-2022-44268>

If we open up `http://pilgrimage.htb`, we can see a form to upload an image to shrink.

![Website](/Pilgrimage/images/website.png)

Let's create the malicious image to exfiltrate the contents ot `/etc/passwd` file.

![Image creation](/Pilgrimage/images/passwd.png)

It generates `image.png` which we can upload. After clicking the Shrink button, it provides us the link of the shrunken image.

![Image Link](/Pilgrimage/images/link.png)

If we click on the link, the image opens in a new tab. We can download the image and use `exiftool` to view the details. The `Raw Profile Type` key holds the data that we need.

![Raw Proffile Type](/Pilgrimage/images/raw_profile.png)

The data is encoded in hexadecimal. We can use xxd to decode it.

![Hex to Text](/Pilgrimage/images/hex_decode.png)

We found the username. Let's repeat the above steps to view the contents of `/var/db/pilgrimage`.

![Hex to Text](/Pilgrimage/images/hex_decode_1.png)

It seems like we got the password for the user. Let's try to SSH into the box.

![SSH](/Pilgrimage/images/ssh.png)

It works. We got the foothold and there is the user flag in `user.txt` file.

![User Flag](/Pilgrimage/images/user_flag.png)

Running `sudo -l` tells us that we cannot run any command as sudo. Let's look at the processes running on the system with `ps aux` command.

![Processes](/Pilgrimage/images/malwarescan.png)

There is a suspicious process running the script `/usr/sbin/malwarescan.sh`. Let's look at the contents of the script.

![Script](/Pilgrimage/images/script.png)

It is using `binwalk`. We can check the version o the `binwalk` with `-h` flag.

![Binwalk](/Pilgrimage/images/binwalk.png)

After a quick Internet search, we find the RCE vulnerability CVE-2022-4510 and an exploit <https://github.com/electr0sm0g/CVE-2022-4510>. It allows us to create a malicious image that we can upload to the machine and get a reverse shell with elevated privileges.

Let's create the malicious image using the tool.

![Malicious Image](/Pilgrimage/images/malicious.png)

We can nou open up a netcat listener at the port used and then upload the malicious image to `/var/www/pilgrimage.htb/shrunk`. After doing so, we get the reverse shell in our netcat listener as the root user.

![Root User](/Pilgrimage/images/root_user.png)