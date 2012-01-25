/* Minimal main program -- everything is loaded from the library */

#include <dlfcn.h>

typedef int (*main_t)(int, char **);

#define PYTHONPATH "/mnt/sdcard/python-extras:/data/data/org.gaeproxy/files/python-extras:/data/data/org.gaeproxy/python/lib/python2.6/lib-dynload"
#define PYTHONHOME "/data/data/org.gaeproxy/python"
#define LD_LIBRARY_PATH "/data/data/org.gaeproxy/python/lib"

int
main(int argc, char **argv)
{
    setenv("PYTHONPATH", PYTHONPATH, 0);
    setenv("PYTHONHOME", PYTHONHOME, 0);
    setenv("LD_LIBRARY_PATH", LD_LIBRARY_PATH, 1);
    void *fd = dlopen("/data/data/org.gaeproxy/python/lib/libpython2.6.so", RTLD_LAZY);
    main_t Py_Main = (main_t) dlsym (fd, "Py_Main");
	int exitcode = Py_Main(argc, argv);
    dlclose(fd);
    return exitcode;
}
