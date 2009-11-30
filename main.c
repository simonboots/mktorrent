#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/errno.h>
#include <string.h>

void print_out(unsigned char *md_value, int md_len);

int main (int argc, const char * argv[]) {
    
    int piece_size = 1024 * 1024;
    int num_pieces;
    
    // File stuff
    char *filename = "/Users/sst/Desktop/1gfile";

    // open file
    int fdes = open(filename, O_RDONLY);    
    if (fdes == -1) {
        printf("Error opening file\n");
        exit(-1);
    }
    
    // get file stats
    struct stat stats;
    int retval = fstat(fdes, &stats);
    if (retval != 0) {
        printf("Error while reading file stats: %d\n", errno);
    }
    
    printf("File size is %d bytes\n", (int)stats.st_size);
    
    // calculate number of pieces
    num_pieces = stats.st_size / piece_size;
    if (stats.st_size % piece_size != 0) num_pieces++;
    
    // alloc memory for hash
    unsigned char *hash = (unsigned char*)malloc(sizeof(unsigned char) * 20 * num_pieces);
        
    // get GCD queues
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_queue_t main = dispatch_get_main_queue();
    dispatch_retain(main);
    dispatch_group_t group = dispatch_group_create();

    // piece block
    void (^PieceBlock)(size_t) = ^(size_t idx) { 
        int start = idx * piece_size;
        char *piece = (char*)malloc(piece_size * sizeof(char));
        
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
        memcpy(&(hash[idx * 20]), md_value, 20);
        
        free(piece);
        //dispatch_sync(main, ^{print_out(idx, md_value, md_len);});
    };
    
    // call PieceBlocks
    dispatch_group_async(group, queue, ^ { dispatch_apply(num_pieces, queue, PieceBlock); } );
    dispatch_group_notify(group, queue, ^ { print_out(hash, 20 * num_pieces);});
    dispatch_release(main);
    
    // run main dispatch run loop
    dispatch_main();

    return 0;
}

void print_out(unsigned char *md_value, int md_len) {
    int i;
    for (i = 0; i < md_len; i++)
    {
        //if (i % 20 == 0) printf("\n");
        printf("%02x", md_value[i]);
    }
    exit(0);
}
