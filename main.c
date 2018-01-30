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
#include <getopt.h>

void print_out(unsigned char *md_value, int md_len);
unsigned char * hash_file(int fd);

int main (int argc, const char * argv[]) {
    
    int filename_fd;
    int outputname_fd;
    int ch;
    
    /* options descriptor */
    static struct option longopts[] = {
        { "output", required_argument, NULL, 'o' }, { NULL, 0, NULL, 0 }
    };
    
    while ((ch = getopt_long(argc, argv, "o:", longopts, NULL)) != 1) {
        switch (ch) {
            case 'o':
                if ((outputname_fd = open(optarg, O_RDWR | O_CREAT, 0)) == -1) printf("unable to open %s", optarg); exit(1); break;
            default:
                printf("Default...\n");
                break;
        }
    }
           
    argc -= optind;
    argv += optind;
           
    if ((filename_fd = open(argv[0], O_RDONLY, 0)) == -1) printf("unable to open %s", argv[0]); exit(2);
    
    hash_file(filename_fd);

    return 0;
}

unsigned char * hash_file(int fd)
{
    int piece_size = 1024 * 1024;
    int num_pieces;
        
    // get file stats
    struct stat stats;
    int retval = fstat(fd, &stats);
    if (retval != 0) {
        printf("Error while reading file stats: %d\n", errno);
        return NULL;
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
        size_t local_piece_size = piece_size;
        int start = idx * piece_size;
        
        char *piece = (char*)malloc(piece_size * sizeof(char));
        
        local_piece_size = pread(fd, piece, local_piece_size, start);
        
        // openssl stuff
        EVP_MD_CTX mdctx;
        const EVP_MD *md = EVP_sha1();
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;
        
        OpenSSL_add_all_digests();
        
        EVP_MD_CTX_init(&mdctx);
        EVP_DigestInit_ex(&mdctx, md, NULL);
        EVP_DigestUpdate(&mdctx, piece, local_piece_size);
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
}

void print_out(unsigned char *md_value, int md_len) {
    int i;
    for (i = 0; i < md_len; i++)
    {
        if (i % 20 == 0) printf("\n");
        printf("%02x", md_value[i]);
    }
    exit(0);
}
