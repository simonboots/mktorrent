#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <fcntl.h>
#include <openssl/evp.h>

void print_out(size_t idx, unsigned char *md_value, int md_len);

int main (int argc, const char * argv[]) {
    
    
    // File stuff
    char *filename = "/Users/sst/Temp/20mfile";
    int piece_size = 1024;
    
    int fdes = open(filename, O_RDONLY);
    
    if (fdes == -1) {
        printf("Error opening file\n");
        exit(-1);
    }
    

        
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_queue_t main = dispatch_get_main_queue();

    dispatch_retain(main);

    void (^MyBlock)(size_t) = ^(size_t idx) { 
        int start = idx * piece_size;
        char piece[1024];
        
        // openssl stuff
        EVP_MD_CTX mdctx;
        const EVP_MD *md = EVP_sha1();
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;
        
        pread(fdes, piece, piece_size, start);
        
        OpenSSL_add_all_digests();
        
        EVP_MD_CTX_init(&mdctx);
        EVP_DigestInit_ex(&mdctx, md, NULL);
        EVP_DigestUpdate(&mdctx, piece, piece_size);
        EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
        EVP_MD_CTX_cleanup(&mdctx);
        
        dispatch_sync(main, ^{print_out(idx, md_value, md_len);});
    };
    
    dispatch_async(queue, ^ { dispatch_apply(100, queue, MyBlock); } );
    
    dispatch_release(main);
    
    
    dispatch_main();

    //printf("Hello, World %d\n", MyBlock(12));
    return 0;
}

void print_out(size_t idx, unsigned char *md_value, int md_len) {
    printf("-> %d: ", (int)idx);
    int i;
    for (i = 0; i < md_len; i++) printf("%02x", md_value[i]);
    printf("\n");
    //exit(0);
}
