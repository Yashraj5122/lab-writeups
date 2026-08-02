# Vaccine

Vaccine is an easy-rated HTB machine, but it packs in a nice chain of small mistakes: an anonymous FTP share leaking a password-protected backup, weak credentials hidden in source code, a SQL injection that gets upgraded into a full OS shell, and a classic GTFOBins privilege escalation to finish it off. Nothing here needs a fancy exploit — it's really a lesson in how quickly things fall apart once one weak link (anonymous FTP) is exposed.

## Recon

Starting off, we're greeted with a login page:

![](assets/Pasted%20image%2020260728053048.png)

An Nmap scan shows that, besides the web server, FTP is also exposed:

![](assets/Pasted%20image%2020260728051624.png)

## Anonymous FTP Access

Since FTP is open, it's worth checking if anonymous login is allowed. Sure enough, it is:

Username: anonymous
Password: anonymous

![](assets/Pasted%20image%2020260728052048.png)

Inside, there's a single file waiting for us — `backup.zip`. Trying to open it, though, we find it's password protected:

![](assets/Pasted%20image%2020260728052625.png)

## Cracking the Zip

Time to bring in John the Ripper. First, we extract a crackable hash from the zip using `zip2john`:

![](assets/Pasted%20image%2020260728052401.png)

Then we throw it at John:

![](assets/Pasted%20image%2020260728052521.png)

The password turns out to be **741852963**.

With the zip unlocked, we find two files inside: `index.php` and `style.css`.

![](assets/Pasted%20image%2020260728052818.png)

## Source Code Review

Reading through `index.php`, a username and password are hardcoded right there in the code:

![](assets/Pasted%20image%2020260728053304.png)

The password is stored as an MD5 hash, so we run it through crackstation.net to recover the plaintext:

![](assets/Pasted%20image%2020260728055617.png)

**Username**: admin
**Password**: qwerty789

## Logging In

With valid credentials in hand, we log into the web application:

![](assets/Pasted%20image%2020260728055707.png)

## SQL Injection → OS Shell

Poking around the dashboard, the search field looks promising — and testing it confirms it's vulnerable to SQL injection:

![](assets/Pasted%20image%2020260728060221.png)

Rather than hand-crafting payloads, we hand this off to SQLMap. First, a quick check of our privileges on the database:

```bash
sqlmap -u "http://10.129.197.174/dashboard.php?search=1" --cookie="PHPSESSID=qf856rqkkd9q0jp2vg3g3pd0k3" --batch --is-dba --privileges
```

![](assets/Pasted%20image%2020260728062107.png)

![](assets/Pasted%20image%2020260728062226.png)

We're a DBA, which means SQLMap can escalate this into a full OS shell:

```bash
sqlmap -u "http://10.129.197.174/dashboard.php?search=1" --cookie="PHPSESSID=qf856rqkkd9q0jp2vg3g3pd0k3" --os-shell --batch
```

![](assets/Pasted%20image%2020260728063329.png)

![](assets/Pasted%20image%2020260728073857.png)

## Finding Postgres Credentials

Poking around the file system from this shell, we stumble across a password for the `postgres` user:

![](assets/Pasted%20image%2020260728075305.png)

User: postgres
Password: P@s5w0rd!

## SSH Access & User Flag

Those credentials work over SSH too:

![](assets/Pasted%20image%2020260728075444.png)

And from here, the user flag is sitting right there:

![](assets/Pasted%20image%2020260728075510.png)

User Flag:
```bash
ec9b13ca4d6229cd5cc1e09980965bf7
```

## Privilege Escalation

Checking `sudo -l`, there's a binary that can be run as root — vi, invoked in a specific way:

![](assets/Pasted%20image%2020260728075702.png)

A quick look at GTFOBins confirms vi can be abused to spawn a root shell. The steps:

- Enter vi
- Type `:set shell=/bin/sh`
- Type `:shell`
- This drops into a shell, but it's still running with the privileges vi was launched with via sudo
- Run the sudo vi command again from inside that shell, and repeat the two `:set shell` / `:shell` steps
- This time, the shell that spawns is a root shell

![](assets/Pasted%20image%2020260728080358.png)

Root Flag:
```bash
dd6e058e814260bc70e9bbdef2715849
```

## Takeaways

- Anonymous FTP access was the initial foothold — always worth checking, even when it seems old-fashioned.
- Hardcoded credentials in source code (even hashed) are a liability once an attacker gets read access to the files.
- SQLMap's `--os-shell` is a fast way to turn a confirmed SQLi with DBA privileges into full command execution.
- Misconfigured `sudo` rules for editors like vi are a textbook GTFOBins privilege escalation — always check `sudo -l` first.
