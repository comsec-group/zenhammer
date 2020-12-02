
typedef struct Flip {
	void* addr;
	size_t mask;
	size_t data;
} Flip;

typedef struct FlipList {
	size_t cnt;
	Flip flips[500];
} FlipList;


void hammer_func(unsigned char* sync_addr, unsigned char** patt, size_t len, size_t rounds);
//void hammer_func(unsigned char* sync_addr, unsigned char** patt, size_t num_refs, size_t max_act, size_t rounds);

FlipList scan(void* base, void* end); 
