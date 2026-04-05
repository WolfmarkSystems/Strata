# Linux Syscall Reference for Developers

## Common Syscalls

### File Operations
```c
// Open, read, write, close
int open(const char *pathname, int flags, mode_t mode);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int close(int fd);

// File info
int stat(const char *pathname, struct stat *statbuf);
int lstat(const char *pathname, struct stat *statbuf);
int fstat(int fd, struct stat *statbuf);

// File manipulation
int truncate(const char *path, off_t length);
int rename(const char *oldpath, const char *newpath);
int unlink(const char *pathname);
int link(const char *oldpath, const char *newpath);
int symlink(const char *target, const char *linkpath);
int mkdir(const char *pathname, mode_t mode);
int rmdir(const char *pathname);
```

### Process Operations
```c
// Process creation
pid_t fork(void);
int execve(const char *pathname, char *const argv[], char *const envp[]);

// Process info
pid_t getpid(void);
pid_t getppid(void);
uid_t getuid(void);
gid_t getgid(void);
pid_t getpgid(pid_t pid);
int setpgid(pid_t pid, pid_t pgid);

// Process control
int kill(pid_t pid, int sig);
unsigned int alarm(unsigned int seconds);
int pause(void);
int exit(int status);
void _exit(int status);
```

### Memory
```c
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);
void *mremap(void *old_address, size_t old_size, size_t new_size, int flags);
int mprotect(void *addr, size_t len, int prot);
int msync(void *addr, size_t len, int flags);
```

### Networking
```c
// Socket
int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

// Send/Receive
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
```

### Time
```c
time_t time(time_t *tloc);
int gettimeofday(struct timeval *tv, struct timezone *tz);
clock_t times(struct tms *buf);
int clock_gettime(clockid_t clock_id, struct timespec *tp);
```

### System Info
```c
int uname(struct utsname *buf);
long sysinfo(struct sysinfo *info);
int gethostname(char *name, size_t len);
int sethostname(const char *name, size_t len);
```

## Linux Forensics Artifacts

### Important Files
```
/etc/passwd - User accounts
/etc/shadow - Password hashes
/etc/group - Group definitions
/etc/sudoers - Sudo permissions
/var/log/syslog - System messages
/var/log/auth.log - Authentication logs
/var/log/messages - General messages
/var/log/secure - Security logs
/var/log/wtmp - Login history
/var/log/lastlog - Last login info
/var/log/faillog - Failed login attempts
```

### User Activity
```
~/.bash_history - Bash command history
~/.zsh_history - Zsh history
~/.ssh/ - SSH keys and config
~/.gnupg/ - GPG keys
~/.config/ - User configurations
~/.local/share/ - User data
```

### System Activity
```
/proc/[pid]/cmdline - Process command
/proc/[pid]/environ - Process environment
/proc/[pid]/fd/ - File descriptors
/proc/[pid]/maps - Memory mappings
/proc/[pid]/status - Process status
/proc/[pid]/exe - Executable path
/proc/mounts - Mounted filesystems
/proc/modules - Loaded kernel modules
/proc/net/* - Network statistics
/proc/sys/ - Kernel parameters
```

### Log Locations by Service
| Service | Log Location |
|---------|--------------|
| SSH | /var/log/auth.log, /var/log/secure |
| Apache | /var/log/apache2/ |
| Nginx | /var/log/nginx/ |
| MySQL | /var/log/mysql/ |
| PostgreSQL | /var/log/postgresql/ |
| Docker | /var/lib/docker/containers/ |
| Systemd | journalctl |

## Linux Memory Forensics

### Volatility Plugins for Linux
```bash
# Process analysis
linux_pslist - List processes
linux_pstree - Process tree
linux_psaux - Process details with arguments

# Memory analysis
linux_memmap - Memory maps
linux_dump_map - Dump memory maps
linux_find_file - Find files in memory
linux_lsmod - Loaded modules

# Network analysis
linux_netscan - Network connections
linux_route_cache - Routing cache

# Keylogging
linux_keyboard_buffer - Keyboard buffer
```

## Linux Malware Analysis

### Common Malicious Indicators
```bash
# Suspicious processes
ps auxf | grep -v grep
ps -eo pid,ppid,%cpu,%mem,tty,stat,time,cmd

# Network connections
netstat -tulpn
ss -tulpn
lsof -i

# Cron jobs
crontab -l
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/

# Startup locations
ls -la /etc/rc.local
ls -la /etc/init.d/
ls -la /etc/profile.d/

# SUID files
find / -perm -4000 -type f 2>/dev/null
find / -perm -6000 -type f 2>/dev/null

# Hidden files
find / -name ".*" -type f 2>/dev/null | head -50

# Recent files
find / -mtime -1 -type f 2>/dev/null
```

## Useful Linux Commands for DFIR

```bash
# Timeline creation
fls -r -m / > body
ils -e body | sort > timeline.txt

# File recovery
extundelete /dev/sda1 --restore-all
foremost -i /dev/sda1 -o output

# Carving
binwalk firmware.bin
foremost -i image.raw -o carved
scalpel -i image.raw -c scalpel.conf

# Memory dump
lime -f lime.elf -o memory.lime
```
