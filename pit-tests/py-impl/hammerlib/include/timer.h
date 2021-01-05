#ifndef TIMER_H
#define TIMER_H

// taken from https://github.com/cloudflare/cloudflare-blog/tree/master/2018-11-memory-refresh
// slightly modified
typedef struct {
	uint32_t t; // timestamp
	uint32_t d; // duration
} delta_t;

delta_t* prfoile_refresh(unsigned char* addr);

size_t time_access(unsigned char* a1, unsigned char* a2, size_t rounds); 

size_t time_patt(unsigned char** patt, size_t len); 

#endif // TIMER_H


