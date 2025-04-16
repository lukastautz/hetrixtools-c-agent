# hetrixtools-c-agent
This is a minimal (and unofficial) agent for HetrixTools written in C. It uses the same API the PHP agent uses, and sadly this API doesn't allow uploading steal statistics, so that won't be shown. I didn't use the v2 API because there much more information needs to be uploaded.

# Resource usage
The agent uses around 100 to 150 KiB of RAM and negligible CPU resources. Compared to the official bash agent, it uses only 3% of the memory and around 1/150th of the CPU time.

# Installation
If you use systemd (I don't like it but it's used by a majority of the distributions), you can simply run the below command to install the agent, unless you want to compile it yourself or run it as a different user:
```
curl -s https://raw.githubusercontent.com/lukastautz/hetrixtools-c-agent/refs/heads/main/systemd_install.sh | bash -s HETRIXTOOLS_SID
```
The HetrixTools token/SID is the 32-character hexadecimal string you can see if you go to "Monitoring Agent Package".

# Compiling it
If you want to compile it, you have to install dietlibc and add `diet` and `elftrunc` to your path (or edit the Makefile to use a different compiler/libc). You can also adjust a few settings in `config.h`.

# Running it as a different user
The program doesn't need to run as root; it only needs read access to `/etc/hetrixtools_agent_token` (and of course network access and access to the relevant `/proc` files). If you want to, you can simply modify the third line of `systemd_install.sh` to your wanted user (and create that user before running the script).
