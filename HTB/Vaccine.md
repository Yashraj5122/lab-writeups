# Vaccine

> **Platform:** Hack The Box
> **Difficulty:** Easy
> **Tags:** `ftp` · `password-cracking` · `hardcoded-creds` · `sqli` · `sqlmap` · `gtfobins`

Vaccine is an easy-rated box, but it packs a really clean little chain of small mistakes stacked on top of each other. Nothing here needs a fancy exploit — it's more a lesson in how fast everything unravels once one weak link (anonymous FTP) is left exposed.

The chain looks like this:

1. **Recon** → nmap finds FTP open alongside the web server.
2. **Foothold** → anonymous FTP leaks a password-protected `backup.zip`; crack it, and the source inside hands over the web app's admin login.
3. **User** → a SQL injection in the dashboard gets upgraded into a full OS shell, which leaks the `postgres` password for SSH.
4. **Root** → a sloppy `sudo` rule for `vi` is a textbook GTFOBins privesc.

It's the kind of box where every step is short, but each one only exists because someone reused or exposed something they shouldn't have. I'll write it up the way it actually went.

## Recon

Straight off the bat we land on a login page:

![](assets/Pasted%20image%2020260728053048.png)

An nmap scan shows that, on top of the web server, FTP is also sitting there exposed:

![](assets/Pasted%20image%2020260728051624.png)

## Anonymous FTP

Whenever FTP is open the first thing worth trying is anonymous login — it costs nothing and pays off surprisingly often. Sure enough, it's allowed here:

- **Username:** `anonymous`
- **Password:** `anonymous`

![](assets/Pasted%20image%2020260728052048.png)

Inside there's a single file waiting for us, `backup.zip`. Naturally, it's password protected:

![](assets/Pasted%20image%2020260728052625.png)

## Cracking the zip

Time for John. First pull a crackable hash out of the archive with `zip2john`:

![](assets/Pasted%20image%2020260728052401.png)

Then throw it at John with a wordlist:

![](assets/Pasted%20image%2020260728052521.png)

The password comes back as **`741852963`**.

With the archive unlocked there are two files inside — `index.php` and `style.css`:

![](assets/Pasted%20image%2020260728052818.png)

## Reading the source

Reading through `index.php`, the developer left the admin credentials hardcoded right there in the code:

![](assets/Pasted%20image%2020260728053304.png)

The password is stored as an MD5 hash, but that's barely a speed bump — a quick lookup on crackstation.net turns it back into plaintext:

![](assets/Pasted%20image%2020260728055617.png)

- **Username:** `admin`
- **Password:** `qwerty789`

Which gets us logged straight into the web app:

![](assets/Pasted%20image%2020260728055707.png)

## SQL injection → OS shell

Poking around the dashboard, the search field looks like the obvious place to test — and it is. A single quote is enough to break the query, confirming it's injectable:

![](assets/Pasted%20image%2020260728060221.png)

Rather than hand-crafting payloads I handed it straight to sqlmap. First a quick check of what privileges we've got on the database:

```bash
sqlmap -u "http://10.129.197.174/dashboard.php?search=1" \
  --cookie="PHPSESSID=qf856rqkkd9q0jp2vg3g3pd0k3" \
  --batch --is-dba --privileges
```

![](assets/Pasted%20image%2020260728062107.png)

![](assets/Pasted%20image%2020260728062226.png)

Turns out we're a DBA, which is the good news — that's enough for sqlmap to drop us an OS shell directly:

```bash
sqlmap -u "http://10.129.197.174/dashboard.php?search=1" \
  --cookie="PHPSESSID=qf856rqkkd9q0jp2vg3g3pd0k3" \
  --os-shell --batch
```

![](assets/Pasted%20image%2020260728063329.png)

![](assets/Pasted%20image%2020260728073857.png)

## User

Poking around the filesystem from that shell, we run into a `postgres` password sitting in a config file:

![](assets/Pasted%20image%2020260728075305.png)

- **User:** `postgres`
- **Password:** `P@s5w0rd!`

And of course those creds are reused for SSH:

![](assets/Pasted%20image%2020260728075444.png)

User flag's right there:

![](assets/Pasted%20image%2020260728075510.png)

```text
ec9b13ca4d6229cd5cc1e09980965bf7
```

## Privilege escalation

First stop on any box, `sudo -l`. There's a rule letting us run `vi` as root against a specific file:

![](assets/Pasted%20image%2020260728075702.png)

`vi` is a classic GTFOBins entry — if you can launch it as root, you can shell out of it. The steps:

- Open the file with the allowed `sudo vi` command.
- `:set shell=/bin/sh`
- `:shell`
- That drops you to a shell running with the privileges vi was launched with.
- Run the `sudo vi` command again from inside that shell and repeat the two steps — this time the shell that spawns is a root shell.

![](assets/Pasted%20image%2020260728080358.png)

Root flag:

```text
dd6e058e814260bc70e9bbdef2715849
```

## Wrap-up

Vaccine is a nice reminder that boxes rarely fall to one big exploit — they fall to a stack of small, ordinary mistakes. Anonymous FTP was the crack in the wall; after that it was just hardcoded creds, weak hashing, an injectable search box, and reused passwords all the way down, finished off by a `sudo` rule that should never have existed. Always try anonymous FTP, always read the source you get your hands on, and always check `sudo -l` first.
