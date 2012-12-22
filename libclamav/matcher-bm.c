/*
 *  Copyright (C) 2007-2009 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <assert.h>
#include "clamav.h"
#include "memory.h"
#include "others.h"
#include "cltypes.h"
#include "matcher.h"
#include "matcher-bm.h"
#include "filetypes.h"
#include "filtering.h"

#include "mpool.h"

#define BM_MIN_LENGTH	3
#define BM_BLOCK_SIZE	3
#define HASH(a,b,c) (211 * a + 37 * b + c)

int cli_bm_addpatt(struct cli_matcher *root, struct cli_bm_patt *pattern, const char *offset)
{
        uint16_t idx, i;
        const unsigned char *pt = pattern->pattern;
        struct cli_bm_patt *prev, *next = NULL;
        int ret;

        //CHR
        //by defaul bm_offmode=0
        //cli_infomsg(NULL,"Loading %s with length=%d,bm_offmode=%d\n",pattern->virname,pattern->length,root->bm_offmode);
        //cli_infomsg(NULL,"root->filter=%ld\n",root->filter);

        //CHR
        //cli_infomsg(NULL,"DEBUG in cli_bm_addpatt load %s\n",pattern->virname);
        //test_hdb
        char * vname=pattern->virname; //CHR
        if(vname) // && vname[5]=='C' && vname[4]=='.'
        if(vname[0]=='t') {
            cli_infomsg(NULL,"DEBUG: in cli_bm_addpatt loading virname=%s\n",pattern->virname);
            cli_infomsg(NULL,"DEBUG: pattern=%s",pattern->pattern);
            cli_infomsg(NULL,"DEBUG: pattern length=%d\n",pattern->length);
            cli_infomsg(NULL,"DEBUG: bm_offmode=%d\n",root->bm_offmode);
            if(root->filter)cli_infomsg(NULL,"DEBUG: filter=1\n"); else cli_infomsg(NULL,"DEBUG: filter=0\n");
        }
        //CHR

        if(pattern->length < BM_MIN_LENGTH) {
                cli_errmsg("cli_bm_addpatt: Signature for %s is too short\n", pattern->virname);
                return CL_EMALFDB;
        }

        if((ret = cli_caloff(offset, NULL, root->type, pattern->offdata, &pattern->offset_min, &pattern->offset_max))) {
                cli_errmsg("cli_bm_addpatt: Can't calculate offset for signature %s\n", pattern->virname);
                return ret;
        }

        //dediacted for virus name as 'test_hdb'
        if(vname) if(vname[0]=='t') cli_infomsg(NULL,"DEBUG: offset=%d\n",offset&&0xFF); //CHR
        if(vname) if(vname[0]=='t') cli_infomsg(NULL,"DEBUG: offdata[0]=%d(1=CLI_OFF_ABSOLUTE)\n",pattern->offdata[0]); //CHR

        if(pattern->offdata[0] != CLI_OFF_ANY) {
                if(pattern->offdata[0] == CLI_OFF_ABSOLUTE)
                        root->bm_absoff_num++;
                else
                        root->bm_reloff_num++;
        }

        /* bm_offmode doesn't use the prefilter for BM signatures anyway, so
         * don't add these to the filter. */
        if(root->filter && !root->bm_offmode) {
                /* the bm_suffix load balancing below can shorten the sig,
                 * we want to see the entire signature! */
                //if(vname) if(vname[0]=='t') cli_infomsg(NULL,"DEBUG: run filter_add_static\n"); //CHR
                //filter_add_static, updating shift-or FSM
                if (filter_add_static(root->filter, pattern->pattern, pattern->length, pattern->virname) == -1) {
                        cli_warnmsg("cli_bm_addpatt: cannot use filter for trie\n");
                        mpool_free(root->mempool, root->filter);
                        root->filter = NULL;
                }
                /* TODO: should this affect maxpatlen? */
        }

#if BM_MIN_LENGTH == BM_BLOCK_SIZE
        /* try to load balance bm_suffix (at the cost of bm_shift) */
        for(i = 0; i < pattern->length - BM_BLOCK_SIZE + 1; i++) {
                idx = HASH(pt[i], pt[i + 1], pt[i + 2]);
                if(vname) if(vname[0]=='t') cli_infomsg(NULL,"DEBUG: hash idx=%d\n",idx);
                if(!root->bm_suffix[idx]) {
                        if(vname) if(vname[0]=='t') cli_infomsg(NULL,"DEBUG: no such idx at i=%d, will break out\n",i); //CHR
                        if(i) {
                                if(vname) if(vname[0]=='t') cli_infomsg(NULL,"DEBUG: load balance i=%d\n",i); //CHR
                                pattern->prefix = pattern->pattern;
                                pattern->prefix_length = i;
                                pattern->pattern = &pattern->pattern[i];
                                pattern->length -= i;
                                pt = pattern->pattern;
                        }
                        break;
                }
        }
#endif

        for(i = 0; i <= BM_MIN_LENGTH - BM_BLOCK_SIZE; i++) {
                idx = HASH(pt[i], pt[i + 1], pt[i + 2]);
                //CHR calc shift with WM algo
                root->bm_shift[idx] = MIN(root->bm_shift[idx], BM_MIN_LENGTH - BM_BLOCK_SIZE - i);
                if(vname) if(vname[0]=='t') cli_infomsg(NULL,"DEBUG: calc shift with WM algo root->bm_shift[%d]=%d\n",idx,root->bm_shift[idx]); //CHR
                //CHR cli_infomsg(NULL,"bm_shift=%d\n", root->bm_shift[idx]);
        }

        // CHR insert to the queue of same hash
        prev = next = root->bm_suffix[idx];
        while(next) {
                if(pt[0] >= next->pattern0)
                        break;
                prev = next; 
                next = next->next;
        }
        // CHR after above actions
        // CHR ( )->( )->( )
        // CHR  ^    ^
        // CHR  |    |
        // CHR prev  netx
        // CHR     ^
        // CHR     |
        // CHR   current one to be inserted here

        if(next == root->bm_suffix[idx]) {
                pattern->next = root->bm_suffix[idx];
                if(root->bm_suffix[idx])
                        pattern->cnt = root->bm_suffix[idx]->cnt;
                root->bm_suffix[idx] = pattern;
        } else {
                pattern->next = prev->next;
                prev->next = pattern;
        }
        pattern->pattern0 = pattern->pattern[0];
        root->bm_suffix[idx]->cnt++;
        //CHR cli_infomsg(NULL,"count=%d\n",root->bm_suffix[idx]->cnt);

        if(root->bm_offmode) { //CHR not bm_offmode(=0) mode
                root->bm_pattab = (struct cli_bm_patt **) mpool_realloc2(root->mempool, root->bm_pattab, (root->bm_patterns + 1) * sizeof(struct cli_bm_patt *));
                if(!root->bm_pattab) {
                        cli_errmsg("cli_bm_addpatt: Can't allocate memory for root->bm_pattab\n");
                        return CL_EMEM;
                }
                root->bm_pattab[root->bm_patterns] = pattern;
                if(pattern->offdata[0] != CLI_OFF_ABSOLUTE)
                        pattern->offset_min = root->bm_patterns;
        }

        root->bm_patterns++;
        //CHR
        //cli_infomsg(NULL,"bm_patterns=%d for type=%d\n",root->bm_patterns,root->type);
        return CL_SUCCESS;
}

int cli_bm_init(struct cli_matcher *root)
{
 
        cli_infomsg(NULL,"DEBUG: init bm shift in cli_ac_init for type %s\n",cli_mtargets[root->type].name); //CHR

        uint16_t i, size = HASH(255, 255, 255) + 1;
#ifdef USE_MPOOL
        assert (root->mempool && "mempool must be initialized");
#endif

        if(!(root->bm_shift = (uint8_t *) mpool_calloc(root->mempool, size, sizeof(uint8_t))))
                return CL_EMEM;

        if(!(root->bm_suffix = (struct cli_bm_patt **) mpool_calloc(root->mempool, size, sizeof(struct cli_bm_patt *)))) {
                mpool_free(root->mempool, root->bm_shift);
                return CL_EMEM;
        }

        for(i = 0; i < size; i++){
                root->bm_shift[i] = BM_MIN_LENGTH - BM_BLOCK_SIZE + 1;
                // SHIFT is inited as 1
                //cli_infomsg(NULL,"bm_shift=%d\n",root->bm_shift[i]);
        }

        return CL_SUCCESS;
}

int cli_bm_initoff(const struct cli_matcher *root, struct cli_bm_off *data, const struct cli_target_info *info)
{
        int ret;
        unsigned int i;
        struct cli_bm_patt *patt;
        //CHR
        cli_infomsg(NULL,"DEBUG in cli_bm_initoff\n");

        if(!root->bm_patterns) {
                data->offtab = data->offset = NULL;
                data->cnt = data->pos = 0;
                return CL_SUCCESS;
        }

        data->cnt = data->pos = 0;
        data->offtab = (uint32_t *) cli_malloc(root->bm_patterns * sizeof(uint32_t));
        if(!data->offtab) {
                cli_errmsg("cli_bm_initoff: Can't allocate memory for data->offtab\n");
                return CL_EMEM;
        }
        data->offset = (uint32_t *) cli_malloc(root->bm_patterns * sizeof(uint32_t));
        if(!data->offset) {
                cli_errmsg("cli_bm_initoff: Can't allocate memory for data->offset\n");
                free(data->offtab);
                return CL_EMEM;
        }
        for(i = 0; i < root->bm_patterns; i++) {
                patt = root->bm_pattab[i];
                if(patt->offdata[0] == CLI_OFF_ABSOLUTE) {
                        data->offtab[data->cnt] = patt->offset_min + patt->prefix_length;
                        if(data->offtab[data->cnt] >= info->fsize)
                                continue;
                        data->cnt++;
                } else if((ret = cli_caloff(NULL, info, root->type, patt->offdata, &data->offset[patt->offset_min], NULL))) {
                        cli_errmsg("cli_bm_initoff: Can't calculate relative offset in signature for %s\n", patt->virname);
                        free(data->offtab);
                        free(data->offset);
                        return ret;
                } else if((data->offset[patt->offset_min] != CLI_OFF_NONE) && (data->offset[patt->offset_min] + patt->length <= info->fsize)) {
                        if(!data->cnt || (data->offset[patt->offset_min] + patt->prefix_length != data->offtab[data->cnt - 1])) {
                                data->offtab[data->cnt] = data->offset[patt->offset_min] + patt->prefix_length;
                                if(data->offtab[data->cnt] >= info->fsize)
                                        continue;
                                data->cnt++;
                        }
                }
        }

        cli_qsort(data->offtab, data->cnt, sizeof(uint32_t), NULL);
        return CL_SUCCESS;
}

void cli_bm_freeoff(struct cli_bm_off *data)
{
        free(data->offset);
        data->offset = NULL;
        free(data->offtab);
        data->offtab = NULL;
}

void cli_bm_free(struct cli_matcher *root)
{
        struct cli_bm_patt *patt, *prev;
        uint16_t i, size = HASH(255, 255, 255) + 1;


        if(root->bm_shift)
                mpool_free(root->mempool, root->bm_shift);

        if(root->bm_pattab)
                mpool_free(root->mempool, root->bm_pattab);

        if(root->bm_suffix) {
                for(i = 0; i < size; i++) {
                        patt = root->bm_suffix[i];
                        while(patt) {
                                prev = patt;
                                patt = patt->next;
                                if(prev->prefix)
                                        mpool_free(root->mempool, prev->prefix);
                                else
                                        mpool_free(root->mempool, prev->pattern);
                                if(prev->virname)
                                        mpool_free(root->mempool, prev->virname);
                                mpool_free(root->mempool, prev);
                        }
                }
                mpool_free(root->mempool, root->bm_suffix);
        }
}

int cli_bm_scanbuff(const unsigned char *buffer, uint32_t length, const char **virname, const struct cli_bm_patt **patt, const struct cli_matcher *root, uint32_t offset, const struct cli_target_info *info, struct cli_bm_off *offdata, uint32_t *viroffset)
{
        uint32_t i, j, off, off_min, off_max;
        uint8_t found, pchain, shift;
        uint16_t idx, idxchk;
        struct cli_bm_patt *p;
        const unsigned char *bp, *pt;
        unsigned char prefix;
        int ret;

        if(viroffset) cli_infomsg(NULL,"DEBUG: in cli_bm_scanbuff viroffset=%d\n",*viroffset); //CHR
        if(viroffset) cli_infomsg(NULL,"DEBUG: buffer=%s",buffer);
        if(offdata)  cli_infomsg(NULL,"DEBUG: in cli_bm_scanbuff have offdata\n"); //CHR
        if(!root || !root->bm_shift)
                return CL_CLEAN;

        if(length < BM_MIN_LENGTH)
                return CL_CLEAN;

        i = BM_MIN_LENGTH - BM_BLOCK_SIZE;
        if(offdata) {
                if(!offdata->cnt)
                        return CL_CLEAN;
                if(offdata->pos == offdata->cnt)
                        offdata->pos--;
                for(; offdata->pos && offdata->offtab[offdata->pos] > offset; offdata->pos--);
                if(offdata->offtab[offdata->pos] < offset)
                        offdata->pos++;
                if(offdata->pos >= offdata->cnt)
                        return CL_CLEAN;
                i += offdata->offtab[offdata->pos] - offset;
        }
        for(; i < length - BM_BLOCK_SIZE + 1; ) {
                idx = HASH(buffer[i], buffer[i + 1], buffer[i + 2]);
                //if(root->bm_suffix[idx]) // CHR
                // cli_infomsg(NULL,"DEBUG: in cli_bm_scanbuff pattern=%s shift=%d\n",root->bm_suffix[idx]->pattern,root->bm_shift[idx]); //CHR
                shift = root->bm_shift[idx];
                //CHR if shift==0, a possible match here, ref: WM go
                if(shift == 0) { // shift=0 mean a possible match entry
                        prefix = buffer[i - BM_MIN_LENGTH + BM_BLOCK_SIZE];
                        p = root->bm_suffix[idx];
                        if(p && p->cnt == 1 && p->pattern0 != prefix) {
                                if(offdata) {
                                        cli_infomsg(NULL,"DEBUG: in cli_bm_scanbuff have offdata\n");//CHR
                                        off = offset + i - BM_MIN_LENGTH + BM_BLOCK_SIZE;
                                        for(; offdata->pos < offdata->cnt && off >= offdata->offtab[offdata->pos]; offdata->pos++);
                                        if(offdata->pos == offdata->cnt || off >= offdata->offtab[offdata->pos])
                                                return CL_CLEAN;
                                        i += offdata->offtab[offdata->pos] - off;
                                } else {
                                        i++;//CHR no match at prefix, move one step forward
                                }
                                continue;
                        }
                        //if(p && viroffset) cli_infomsg(NULL,"DEBUG: in cli_bm_scanbuff virname=%s, pattern=%s,p->cnt=%d, prefix_match=%d, p->pattern0=%c, prefix=%c,\n",p->virname,p->pattern,p->cnt,p->pattern0==prefix,p->pattern0,prefix); //CHR if(viroffset) means not in init mode
                        //CHR either !p or p->cnt!=1 or pattern0==prefix
                        //CHR case !p move one step forward
                        pchain = 0;
                        while(p) {
                                if(p->pattern0 != prefix) {// CHR no match in prerfix, should check next item in list
                                        if(pchain) //CHR if we are in chain mode, and one dismatch in one pattern of the chain list, we need to quit the loop for further checking(assume the chain should be sorted with alphabet order)
                                                break; // CHR out of loop and move one step forward
                                        p = p->next; // CHR try next pattern in list
                                        continue; // CHR check next pattern in list
                                } else pchain = 1; //CHR p->pattern0=prefix, mark that we are in chain mode before further checking current pattern

                                off = i - BM_MIN_LENGTH + BM_BLOCK_SIZE; //CHR get current pos in pattern also make room for basic block in match algo, but in current version BM_MIN_LENGTH==BM_BLOCK_SIZE, no additional offset is added
                                bp = buffer + off;
                                //CHR we are in edge of pattern or string
                                if((off + p->length > length) || (p->prefix_length > off)) {
                                        p = p->next;
                                        continue; //CHR check next pattern in list
                                }

                                if(offdata) {
                                        if(p->offdata[0] == CLI_OFF_ABSOLUTE) {
                                                if(p->offset_min != offset + off - p->prefix_length) {
                                                        p = p->next;
                                                        continue;
                                                }
                                        } else if((offdata->offset[p->offset_min] == CLI_OFF_NONE) || (offdata->offset[p->offset_min] != offset + off - p->prefix_length)) {
                                                p = p->next;
                                                continue;
                                        }
                                }

                                idxchk = MIN(p->length, length - off) - 1; // CHR define checking length
                                if(idxchk) {
                                        //CHR two check points: check offset of idxchk against current pos of string and last char of pattern and also do checking half of the offset in string and pattern
                                        if((bp[idxchk] != p->pattern[idxchk]) ||  (bp[idxchk / 2] != p->pattern[idxchk / 2])) {
                                                p = p->next;
                                                continue; //CHR check next pattern in list
                                        }
                                }
                                //CHR if reach here, means two check points are match, need to further comparison
                                if(p->prefix_length) {
                                        //CHR if load balanced by prefix before, we need to move backward a little bit to prepare a full match against the pattern
                                        off -= p->prefix_length;
                                        bp -= p->prefix_length;
                                        pt = p->prefix;
                                } else {
                                        pt = p->pattern;
                                }
                                //CHR now pt is point at the 'original' pattern
                                found = 1; // CHR assume a match here
                                //CHR scanning over whole pattern
                                //CHR exit condition:
                                //CHR 1. (j>=p->length + p->prefix_length) scanning over whole pattern
                                //CHR 2. (off >= length) off is beyond the string
                                for(j = 0; j < p->length + p->prefix_length && off < length; j++, off++) {
                                        //CHR
                                        if(viroffset){
                                            if(bp[j] == pt[j])
                                            cli_infomsg(NULL,"DEBUG: in cli_bm_scanbuff matching: bp[%d]==pt[%d]==%c\n",j,j,bp[j]);
                                        }
                                        //CHR
                                        if(bp[j] != pt[j]) { // CHR break on any mismatch along the way
                                                found = 0;
                                                break;
                                        }
                                }

                                //CHR at this point a full match is assumed
                                if(viroffset) cli_infomsg(NULL,"DEBUG: in cli_bm_scanbuff p->boundary=%d\n",p->boundary);
                                //CHR boundary==0 in this case
                                if(found && (p->boundary & BM_BOUNDARY_EOL)) {
                                        if(off != length) {
                                                p = p->next;
                                                continue;
                                        }
                                }
                                if(viroffset) cli_infomsg(NULL,"DEBUG: in cli_bm_scanbuff offdata=%d, p->offset_min=%d, p->offdata[0]=%d\n",offdata,p->offset_min,p->offdata[0]);//CHR
                                if(found && p->length + p->prefix_length == j) {
                                        if(!offdata && (p->offset_min != CLI_OFF_ANY)) {
                                                if(p->offdata[0] != CLI_OFF_ABSOLUTE) { //CHR p->offdata[0]==CLI_OFF_ABSOLUTE in this case
                                                        if(!info) {
                                                                p = p->next;
                                                                continue;
                                                        }
                                                        ret = cli_caloff(NULL, info, root->type, p->offdata, &off_min, &off_max);
                                                        if(ret != CL_SUCCESS) {
                                                                cli_errmsg("cli_bm_scanbuff: Can't calculate relative offset in signature for %s\n", p->virname);
                                                                return ret;
                                                        }
                                                } else {
                                                        off_min = p->offset_min;
                                                        off_max = p->offset_max;
                                                }
                                                if(viroffset) cli_infomsg(NULL,"DEBUG: in cli_bm_scanbuff off_min=%d, off_max=%d\n",off_min,off_max);//CHR
                                                off = offset + i - p->prefix_length - BM_MIN_LENGTH + BM_BLOCK_SIZE;
                                                if(viroffset) cli_infomsg(NULL,"DEBUG: in cli_bm_scanbuff off=%d, offset=%d, i=%d,  p->prefix_length=%d\n",off,offset,i,p->prefix_length);//CHR
                                                if(off_min == CLI_OFF_NONE || off_max < off || off_min > off) {
                                                        p = p->next;
                                                        continue;
                                                }
                                        }
                                        if(virname) {
                                                *virname = p->virname;
                                                if(viroffset)
                                                        *viroffset = offset + i + j - BM_MIN_LENGTH + BM_BLOCK_SIZE;
                                        }
                                        if(patt)
                                                *patt = p;
                                        if(viroffset) cli_infomsg(NULL,"DEBUG: pattern=%s",p->pattern);
                                        if(viroffset) cli_infomsg(NULL,"DEBUG: virus=%s\n",p->virname); //CHR
                                        return CL_VIRUS;
                                }
                                p = p->next;
                        }
                        shift = 1;
                }

                if(offdata) {
                        off = offset + i - BM_MIN_LENGTH + BM_BLOCK_SIZE;
                        for(; offdata->pos < offdata->cnt && off >= offdata->offtab[offdata->pos]; offdata->pos++);
                        if(offdata->pos == offdata->cnt || off >= offdata->offtab[offdata->pos])
                                return CL_CLEAN;
                        i += offdata->offtab[offdata->pos] - off;
                } else {
                        i += shift;
                }

        }

        if(viroffset) cli_infomsg(NULL,"DEBUG: CL_CLEAN\n"); //CHR
        return CL_CLEAN;
}
