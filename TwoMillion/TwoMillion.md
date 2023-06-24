# Hack The Box Writeup - TwoMillion (Easy)

![TwoMillionCard](/TwoMillion/images/TwoMillion.png)

As always, we start with a nmap scan. The output reveals that the machine has two ports open: 22 (ssh) and 80 (http).

![Nmap Scan](/TwoMillion/images/nmap.png)

It also reveals that the http-title redirected to `http://2million.htb/`. So let's go ahead and put that in our `/etc/hosts`

![Domain](/TwoMillion/images/domain.png)

Now if we open up `http://2million.htb`, we get a website about Hack The Box.

![Website](/TwoMillion/images/website.png)

The website provides information about the HTB platform. Following the links in the navbar, we get to `/invite` page. There is a form where you can enter the invite code. Let's try random input.

![Invite](/TwoMillion/images/invite.png)

We get a popup saying that the invite code is invalid. There is also a login page link in the navbar that takes us to `/login`. Entering some random email and password tells us that the user is not found.

Back at the `/invite` page, if we view the page source, we see that there is a script at `/js/inviteapi.min.js`. Well, that looks interesting.

![Source](/TwoMillion/images/source.png)

Viewing the contents of the script, it appears to be obfuscated JavaScript code.

![Code](/TwoMillion/images/code.png)

Let's try to deobfuscate it.

![Deobfuscation](/TwoMillion/images/deobfuscation.png)

It looks like we can generate invite code at `/api/v1/invite/how/to/generate`. It requires a post request though. Let's use curl to send the POST request. The response is a json object so let's pipe it through `jq` so that we can see the result a bit better.

![Hint](/TwoMillion/images/hint.png)

The data seems to be encrypted with ROT13. There is a hint as well which says that we should try to decrypt it. Let's see what we get.

![Rot13](/TwoMillion/images/rot13.png)

It says that in order to generate the invite code, we need to make a POST request to `/api/v1/invite/generate`. Let's try that.

![Encoded](/TwoMillion/images/encoded.png)

The code is appears to be encoded in base64 as we can see there is '=' at the end of the string. Let's try to decode the code.

![Decoded](/TwoMillion/images/decoded.png)

Cool, we get the decoded code. Let's try that in the `/invite` page.

![Register](/TwoMillion/images/register.png)

We get redirected to `/register`. After filling in the form and submitting, we get redirected to `/login`. If we enter the credentials we used for registering, we get signed in to the dashboard at `/home`.

![Dashboard](/TwoMillion/images/dashboard.png)

Looking around the page and opening the links, there is not much that you can do.There is however, `/home/access` page that allows you to download openvpn file. That seems interesting.

![Openvpn](/TwoMillion/images/openvpn.png)

There is not much useful information in the downloaded file. Let's try to intercept the request using Burp Suite to examine further.

![Proxy](/TwoMillion/images/proxy.png)

Let's change GET request to see what we can find.

Requesting `/api/v1/user/vpn/` and `/api/v1/user` gives us nothing but requesting `/api/v1` provides us information about the available APIs.

![Apis](/TwoMillion/images/apis.png)

We see that there are admin APIs available. Let's try to access them.

![Auth](/TwoMillion/images/auth.png)

Accessing `/api/v1/admin/auth` returns with `"message": false` indicating that we are not admin user. But there is `/api/v1/admin/settings/update` that can be used to update user settings. Let's access that to see what happens.

![Invalid_Content-Type](/TwoMillion/images/invalid_content_type.png)

After sending PUT request, we get response saying invalid content type. Let's update the header to use "Content-Type: application/json".

![Missing Email](/TwoMillion/images/missing_email.png)

After that update, we get the response saying missing parameter email. Let's add that to our request.

![Missing Admin](/TwoMillion/images/missing_is_admin.png)

Sending the request again, we get the message saying missing parameter is_admin. Let's add that as well.

![0 or 1](/TwoMillion/images/0or1.png)

Sending with is_admin:true tells us that is_admin takes 0 or 1. Let's fix that.

![Admin](/TwoMillion/images/admin.png)

After that, we get the response showing that we now have admin previleges.

![Username](/TwoMillion/images/username.png)

If we now send POST request to `/api/v1/vpn/generate`, we get response saying we need username parameter.

![Command Injection](/TwoMillion/images/command_injection.png)

If we include the username in the request, we get the openvpn file like previously which is not very useful. But if we change the username a little, we can get the command injection.

Let's try to get the reverse shell now.

![Foothold](/TwoMillion/images/foothold.png)

We have our foothold. Let's look around and see what we can find.

![Env](/TwoMillion/images/env.png)

The `.env` file looks interesting.

![Password](/TwoMillion/images/password.png)

There is username and password for the admin user of the database. Let's see the available users in the system by printing the contents of the `/etc/passwd`

![Passwd](/TwoMillion/images/passwd.png)

We see that there is a user with admin username. Let's try to ssh into the machine with the password that we just found.

![Ssh](/TwoMillion/images/ssh.png)

Indeed it is the correct password. we have access to the admin user now. The user flag is in the user.txt file in the home directory of admin user.

![User Flag](/TwoMillion/images/user_flag.png)

Let's try to escalate our priveleges now. Running `sudo -l` tells us that we are not allowed to run sudo on the machine as admin user.

Looking around the filesystem, we come across a mail that has been left for the admin user in the `/var/mail/admin`

![Vulnerability](/TwoMillion/images/vulnerability.png)

It talks about the OverlaysFS Vulnerability. After some research on the Internet, the system seems to be vulnerable. The exploit for this vulnerability is also available on github <https://github.com/xkaneiki/CVE-2023-0386>.

Let's quickly download the exploit and put it in the `/tmp` directory.

![Upload](/TwoMillion/images/upload.png)

The Instruction on the exploit page says that we need two terminals to execute the exploit. So, let's open up another terminal and ssh into the target. Following the instructions provided in the exploit, we get the root shell.

![Make All](/TwoMillion/images/make_all.png)

![Root](/TwoMillion/images/root.png)

The root flag is at `/root/root.txt`

![Root Flag](/TwoMillion/images/root_flag.png)
