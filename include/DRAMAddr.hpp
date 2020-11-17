
#include <map> 
#include <vector>
#include <string>

#define CHANS(x) ((x)<<(8*3))
#define DIMMS(x) ((x)<<(8*2))
#define RANKS(x) ((x)<<(8*1))
#define BANKS(x) ((x)<<(8*0))
#define MEM_CONFIG(ch,d,r,b) (CHANS(ch) | DIMMS(d) | RANKS(r) | BANKS(b))

#define MTX_SIZE (30)

typedef size_t mem_config_t;

typedef struct {
	size_t BK_SHIFT;
	size_t BK_MASK;
	size_t ROW_SHIFT;
	size_t ROW_MASK;
	size_t COL_SHIFT;
	size_t COL_MASK;	
	size_t DRAM_MTX[MTX_SIZE];
	size_t ADDR_MTX[MTX_SIZE];
} MemConfiguration;

class DRAMAddr {
	private:
	// Class attributes	
		static std::map<size_t, MemConfiguration> Configs;
	      	static MemConfiguration MemConfig;	
		static size_t base_msb;
		
		size_t linearize(); 
	
	public:

		size_t bank;
		size_t row;
		size_t col;

		// class methods
		static void set_base(void* buff);

		static void load_mem_config(mem_config_t cfg); 


		// instance methods
		DRAMAddr(size_t bk, size_t r, size_t c); 

		DRAMAddr(void* addr); 
		
		void* to_virt();

		std::string to_string();


};
