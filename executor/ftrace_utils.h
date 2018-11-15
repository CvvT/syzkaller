#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#define MAX_PATH 256
#define _STR(x) #x
#define STR(x) _STR(x)

int trace_fd;
int marker_fd;
static char *find_debugfs(void)
{
    static char debugfs[MAX_PATH+1];
    static int debugfs_found;
    char type[100];
    FILE *fp;

    if (debugfs_found)
	    return debugfs;

    if ((fp = fopen("/proc/mounts","r")) == NULL)
	    return NULL;

    while (fscanf(fp, "%*s %"
		  STR(MAX_PATH)
		  "s %99s %*s %*d %*d\n",
		  debugfs, type) == 2) {
	    if (strcmp(type, "debugfs") == 0)
		    break;
    }
    fclose(fp);

    if (strcmp(type, "debugfs") != 0)
	    return NULL;

    debugfs_found = 1;

    return debugfs;
}

void enable_trace(const char *event) {
	char *debugfs;
	char path[2048]={0};
	int tmp_fd;
	debugfs = find_debugfs();
	if(debugfs){
		strcpy(path, debugfs);
		strcat(path, event);
		tmp_fd = open(path, O_WRONLY);
		if(tmp_fd >= 0) {
			if (write(tmp_fd, "1", 1) <= 0)
				perror("Write");
		} else{
			perror("open");
		}
	}
	else{
		printf("Can not find debugfs :(");
	}
	return;
}

void enable_trace_kmem_cache_free()
{
	enable_trace("/tracing/events/kmem/kmem_cache_free/enable");
}
void enable_trace_kfree()
{
	enable_trace("/tracing/events/kmem/kfree/enable");
}
void enable_trace_kmalloc()
{
	enable_trace("/tracing/events/kmem/kmalloc/enable");
}
void enable_trace_kmem_cache_alloc_node()
{
	enable_trace("/tracing/events/kmem/kmem_cache_alloc_node/enable");
}
void enable_trace_kmem_cache_alloc()
{
	enable_trace("/tracing/events/kmem/kmem_cache_alloc/enable");
}
void enable_trace_kmalloc_node()
{
	enable_trace("/tracing/events/kmem/kmalloc_node/enable");
}

void enalbe_trace_mm_page_alloc() {
	enable_trace("/tracing/events/kmem/mm_page_alloc/enable");
}

void init_marker_fd()
{
	char *debugfs;
	char path[2048]={0};
	debugfs = find_debugfs();
	printf("%s\n",debugfs);
	if(debugfs){
		strcpy(path, debugfs);
		strcat(path, "/tracing/tracing_on");
		trace_fd = open(path, O_WRONLY);
		if(trace_fd >= 0)
			if (write(trace_fd, "1", 1) <= 0)
				perror("Write");

		strcpy(path, debugfs);
		strcat(path, "/tracing/trace_marker");
		marker_fd = open(path, O_WRONLY);
	}
	else{
		printf("Can not find debugfs :(");
	}
	return;
}

void write_marker_syscall_start(int idx){
	char marker[100]={0};
	sprintf(marker, "start calling syscall number: %d", idx);
	if (write(marker_fd, marker, strlen(marker)) != (int)strlen(marker))
		perror("Write");
	return;
}

void write_marker_syscall_end(int idx){
	char marker[100]={0};
	sprintf(marker, "finish calling syscall number: %d", idx);
	if (write(marker_fd, marker, strlen(marker)) != (int)strlen(marker))
		perror("Write");
	return;
}

void dump_ftrace_atexit(){
	char *debugfs;
	char path[2048] = {0};
	close(marker_fd);
	debugfs = find_debugfs();	
	printf("%s\n",debugfs);
	if(debugfs){
		strcpy(path, debugfs);
		strcat(path, "/tracing/tracing_on");
		trace_fd = open(path, O_WRONLY);
		if(trace_fd >=0 )
			if (write(trace_fd, "0", 1) <= 0)
				perror("Write");
	}
	return;
}

static void output(const char* msg, ...)
{
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fflush(stderr);
}

int fd_set_blocking(int fd, int blocking) {
    /* Save the current flags */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return 0;

    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags) != -1;
}

static FILE *trace_file = NULL;
static char *line = NULL;
void dump_ftrace() {
	char* debugfs;
	char path[256] = {0};
	size_t len = 512;
	int nread;

	if (trace_file == NULL) {
		debugfs = find_debugfs();
		if (debugfs) {
			strcpy(path, debugfs);
			strcat(path, "/tracing/trace");
			if ((trace_file = fopen(path, "r")) < 0) {
				output("Open trace_pipe error\n");
			}
			fd_set_blocking(fileno(trace_file), 0);
		} else {
			output("Open debugfs failed\n");
		}
		line = (char*)malloc(len);
	}

	if (trace_file != NULL) {
		while ((nread = getline(&line, &len, trace_file)) != -1) {
			line[nread] = '\0';
			output("%s", line);
		}

		fclose(trace_file);
		trace_file = NULL;
	}
}

void set_ftrace_buffer_size(){
	int tmp_fd;
	char *debugfs;
	char path[2048] = {0};
	debugfs = find_debugfs();	
	if(debugfs){
		strcpy(path, debugfs);
		strcat(path, "/tracing/buffer_size_kb");
		tmp_fd = open(path, O_WRONLY);
		if(trace_fd >=0 ){
			if (write(trace_fd, "50000", 5) != 5)
				perror("Write");
			close(tmp_fd);	
		}
		else{
			printf("failed to set buffer_size\n");
		}
	}
	return;

}
void set_dump_all_cpus(){
	int tmp_fd;
	char path[] = "/proc/sys/kernel/ftrace_dump_on_oops";
	tmp_fd = open(path, O_WRONLY);
	if(tmp_fd >= 0){
		if(write(tmp_fd, "1", 1) < 0)
			goto error;
	}
	else{
error:
		printf("failed to set ftrace_dump_on_oops");
	}
	return;
}

int contains(char *line, int pid) {
	char pid_str[12] = {0};
	char *token = strtok(line, " ");

	sprintf(pid_str, "%d", pid);
	while (token != NULL) {
		if (!strcmp(token, pid_str))
			return 1;
		token = strtok(NULL, " ");
	}
	return 0;
}

void set_trace_thread(pid_t pid) {
	char path[512] = {0};
	char *debugfs;
	char line[512];
	int fd = 0;
	int s;
	debugfs = find_debugfs();
	if (debugfs) {
		sprintf(path, "%s/%s", debugfs, "tracing/set_event_pid");
		if ((fd = open(path, O_RDONLY)) > 0) {
			if ((s = read(fd, line, 512)) == -1) {
				perror("read error");
				return;
			}
			line[s] = '\0';
			if (s > 0 && line[s-1] == '\n') {
				line[s-1] = '\0';
			}
			close(fd);

			printf("[IN]%s\n", line);
			if (contains(line, pid)) {
				return;
			}

			s = sprintf(line, "%s %d", line, pid);
			printf("[Out]%s\n", line);
			
			if ((fd = open(path, O_WRONLY)) < 0) {
				perror("Open Error\n");
				return;
			}
			if (write(fd, line, s) <= 0)
				perror("failed to write\n");
			close(fd);
		}
	}
}