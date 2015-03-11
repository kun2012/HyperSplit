/*-----------------------------------------------------------------------------
 *
 *  Name:           hs.c
 *  Description:    hyper-split packet classification algorithm
 *  Version:        1.0 (release)
 *  Author:         Yaxuan Qi (yaxuan.qi@gmail.com)
 *  Date:           07/15/2008 ~ 07/28/2008
 *
 *  comments:
 *                  1) refine the code from UCSD
 *                  2) add quad and oct search
 *
 *  Modified by kun as marked.
 *
 *-----------------------------------------------------------------------------*/

#ifndef  _HS_C
#define  _HS_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "hs.h"

/*-----------------------------------------------------------------------------
 *  globals
 *-----------------------------------------------------------------------------*/
int trace_rule_num; //kun
FILE *fpt;  //Added by kun for trace file
//Trace reading, kun
struct flow* read_trace_file(FILE* traceFile) {
    struct flow *flows = new struct flow[MAX_TRACES];
    trace_rule_num = 0;
    int ret = 0;
    while (true) {
        struct flow f;
        int ret = fscanf(traceFile, "%u %u %u %u %u %u", &f.src_ip, &f.dst_ip, &f.src_port, &f.dst_port, &f.proto, &f.trueRID);
        if (ret != 6)
            break;
        flows[trace_rule_num++] = f;
    }
    fclose(traceFile);
    return flows;
}

unsigned int    gChildCount = 0;
unsigned int    gNumTreeNode = 0;
unsigned int    gNumLeafNode = 0;
unsigned int    gWstDepth = 0;
unsigned int    gAvgDepth = 0;
unsigned int    gNumNonOverlappings[DIM];
unsigned long long  gNumTotalNonOverlappings = 1;

struct timeval  gStartTime,gEndTime;

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  ReadIPRange
 *  Description:
 * =====================================================================================
 */
void ReadIPRange(FILE* fp, unsigned int* IPrange)
{
    /*asindmemacces IPv4 prefixes*/
    /*temporary variables to store IP range */
    unsigned int trange[4];
    unsigned int mask;
    char validslash;
    int masklit1;
    unsigned int masklit2,masklit3;
    unsigned int ptrange[4];
    int i;
    /*read IP range described by IP/mask*/
    /*fscanf(fp, "%d.%d.%d.%d/%d", &trange[0],&trange[1],&trange[2],&trange[3],&mask);*/
    if (4 != fscanf(fp, "%d.%d.%d.%d", &trange[0],&trange[1],&trange[2],&trange[3])) {
        printf ("\n>> [err] ill-format IP rule-file\n");
        exit (-1);
    }
    if (1 != fscanf(fp, "%c", &validslash)) {
        printf ("\n>> [err] ill-format IP slash rule-file\n");
        exit (-1);
    }
    /*deal with default mask*/
    if(validslash != '/')
        mask = 32;
    else {
        if (1 != fscanf(fp,"%d", &mask)) {
            printf ("\n>> [err] ill-format mask rule-file\n");
            exit (-1);
        }
    }
    mask = 32 - mask;
    masklit1 = mask / 8;
    masklit2 = mask % 8;

    for(i=0;i<4;i++)
        ptrange[i] = trange[i];

    /*count the start IP */
    for(i=3;i>3-masklit1;i--)
        ptrange[i] = 0;
    if(masklit2 != 0){
        masklit3 = 1;
        masklit3 <<= masklit2;
        masklit3 -= 1;
        masklit3 = ~masklit3;
        ptrange[3-masklit1] &= masklit3;
    }
    /*store start IP */
    IPrange[0] = ptrange[0];
    IPrange[0] <<= 8;
    IPrange[0] += ptrange[1];
    IPrange[0] <<= 8;
    IPrange[0] += ptrange[2];
    IPrange[0] <<= 8;
    IPrange[0] += ptrange[3];

    /*count the end IP*/
    for(i=3;i>3-masklit1;i--)
        ptrange[i] = 255;
    if(masklit2 != 0){
        masklit3 = 1;
        masklit3 <<= masklit2;
        masklit3 -= 1;
        ptrange[3-masklit1] |= masklit3;
    }
    /*store end IP*/
    IPrange[1] = ptrange[0];
    IPrange[1] <<= 8;
    IPrange[1] += ptrange[1];
    IPrange[1] <<= 8;
    IPrange[1] += ptrange[2];
    IPrange[1] <<= 8;
    IPrange[1] += ptrange[3];
}

void ReadPort(FILE* fp, unsigned int* from, unsigned int* to)
{
    unsigned int tfrom;
    unsigned int tto;
    if ( 2 !=  fscanf(fp,"%d : %d",&tfrom, &tto)) {
        printf ("\n>> [err] ill-format port range rule-file\n");
        exit (-1);
    }
    *from = tfrom;
    *to = tto;
}

void ReadProtocol(FILE* fp, unsigned int* from, unsigned int* to)
{
    //TODO: currently, only support single protocol, or wildcard
    char dump=0;
    unsigned int proto=0,len=0;
    if ( 7 != fscanf(fp, " %c%c%x%c%c%c%x",&dump,&dump,&proto,&dump,&dump,&dump,&len)) {
        printf ("\n>> [err] ill-format protocol rule-file\n");
        exit (-1);
    }
    if (len==0xff) {
        *from = proto;
        *to = *from;
    } else {
        *from = 0x0;
        *to = 0xff;
    }
}


int ReadFilter(FILE* fp, struct FILTSET* filtset,   unsigned int cost)
{
    /*allocate a few more bytes just to be on the safe side to avoid overflow etc*/
    char validfilter;   /* validfilter means an '@'*/
    struct FILTER *tempfilt,tempfilt1;

    while (!feof(fp))
    {

        if ( 0 != fscanf(fp,"%c",&validfilter)) {
            /*printf ("\n>> [err] ill-format @ rule-file\n");*/
            /*exit (-1);*/
        }
        if (validfilter != '@') continue;   /* each rule should begin with an '@' */

        tempfilt = &tempfilt1;
        ReadIPRange(fp,tempfilt->dim[0]);                   /* reading SIP range */
        ReadIPRange(fp,tempfilt->dim[1]);                   /* reading DIP range */

        ReadPort(fp,&(tempfilt->dim[2][0]),&(tempfilt->dim[2][1]));
        ReadPort(fp,&(tempfilt->dim[3][0]),&(tempfilt->dim[3][1]));

        ReadProtocol(fp,&(tempfilt->dim[4][0]),&(tempfilt->dim[4][1]));

        /*read action taken by this rule
                fscanf(fp, "%d", &tact);
                tempfilt->act = (unsigned char) tact;

        read the cost (position) , which is specified by the last parameter of this function*/
        tempfilt->cost = cost;

        // copy the temp filter to the global one
        memcpy(&(filtset->filtArr[filtset->numFilters]),tempfilt,sizeof(struct FILTER));

        filtset->numFilters++;
        return SUCCESS;
    }
    return FALSE;
}


void LoadFilters(FILE *fp, struct FILTSET *filtset)
{
    int line = 0;
    filtset->numFilters = 0;
    while(!feof(fp))
    {
        ReadFilter(fp,filtset,line);
        line++;
    }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:    ReadFilterFile
 *  Description:    Read rules from file.
 *                  Rules are stored in 'filterset' for range matching
 * =====================================================================================
 */
int ReadFilterFile(rule_set_t*  ruleset, char* filename)
{
    int     i, j;
    FILE*   fp;
    struct FILTSET  filtset;        /* filter set for range match */


    fp = fopen (filename, "r");
    if (fp == NULL)
    {
        printf("Couldnt open filter set file \n");
        return  FAILURE;
    }

    LoadFilters(fp, &filtset);
    fclose(fp);

    /*
     *yaxuan: copy rules to dynamic structrue, and from now on, everything is new:-)
     */
    ruleset->num = filtset.numFilters;
    ruleset->ruleList = (rule_t*) malloc(ruleset->num * sizeof(rule_t));
    for (i = 0; i < ruleset->num; i++) {
        ruleset->ruleList[i].pri = filtset.filtArr[i].cost;
        for (j = 0; j < DIM; j++) {
            ruleset->ruleList[i].range[j][0] = filtset.filtArr[i].dim[j][0];
            ruleset->ruleList[i].range[j][1] = filtset.filtArr[i].dim[j][1];
        }
    }
    /*printf("\n>>number of rules loaded from file: %d", ruleset->num);*/

    return  SUCCESS;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Compare
 *  Description:  for qsort
 *     Comments:  who can make it better?
 * =====================================================================================
 */
int SegPointCompare (const void * a, const void * b)
{
    if ( *(unsigned int*)a < *(unsigned int*)b )
        return -1;
    else if ( *(unsigned int*)a == *(unsigned int*)b )
        return 0;
    else
        return 1;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  BuildHSTree
 *  Description:  building hyper-splitting tree via recursion
 * =====================================================================================
 */
int BuildHSTree (rule_set_t* ruleset, hs_node_t* currNode, unsigned int depth)
{
    /* generate segments for input filtset */
    unsigned int    dim, num, pos;
    unsigned int    maxDiffSegPts = 1;  /* maximum different segment points */
    unsigned int    d2s = 0;        /* dimension to split (with max diffseg) */
    unsigned int    thresh;
    unsigned int    range[2][2];    /* sub-space ranges for child-nodes */
    unsigned int    *segPoints[DIM];
    unsigned int    *segPointsInfo[DIM];
    unsigned int    *tempSegPoints;
    unsigned int    *tempRuleNumList;
    float           hightAvg, hightAll;
    rule_set_t      *childRuleSet;

#ifdef  DEBUG
    /*if (depth > 10)   exit(0);*/
    printf("\n\n>>BuildHSTree at depth=%d", depth);
    printf("\n>>Current Rules:");
    for (num = 0; num < ruleset->num; num++) {
        printf ("\n>>%5dth Rule:", ruleset->ruleList[num].pri);
        for (dim = 0; dim < DIM; dim++) {
            printf (" [%-8x, %-8x]", ruleset->ruleList[num].range[dim][0], ruleset->ruleList[num].range[dim][1]);
        }
    }
#endif /* DEBUG */

    /*Generate Segment Points from Rules*/
    for (dim = 0; dim < DIM; dim ++) {
        /* N rules have 2*N segPoints */
        segPoints[dim] = (unsigned int*) malloc ( 2 * ruleset->num * sizeof(unsigned int));
        segPointsInfo[dim] = (unsigned int*) malloc ( 2 * ruleset->num * sizeof(unsigned int));
        for (num = 0; num < ruleset->num; num ++) {
            segPoints[dim][2*num] = ruleset->ruleList[num].range[dim][0];
            segPoints[dim][2*num + 1] = ruleset->ruleList[num].range[dim][1];
        }
    }
    /*Sort the Segment Points*/
    for(dim = 0; dim < DIM; dim ++) {
        qsort(segPoints[dim], 2*ruleset->num, sizeof(unsigned int), SegPointCompare);
    }

    /*Compress the Segment Points, and select the dimension to split (d2s)*/
    tempSegPoints  = (unsigned int*) malloc(2 * ruleset->num * sizeof(unsigned int));
    hightAvg = 2*ruleset->num + 1;
    for (dim = 0; dim < DIM; dim ++) {
        unsigned int    i, j;
        unsigned int    *hightList;
        unsigned int    diffSegPts = 1; /* at least there are one differnt segment point */
        tempSegPoints[0] = segPoints[dim][0];
        for (num = 1; num < 2*ruleset->num; num ++) {
            if (segPoints[dim][num] != tempSegPoints[diffSegPts-1]) {
                tempSegPoints[diffSegPts] = segPoints[dim][num];
                diffSegPts ++;
            }
        }
        /*Span the segment points which is both start and end of some rules*/
        pos = 0;
        for (num = 0; num < diffSegPts; num ++) {
            int i;
            int ifStart = 0;
            int ifEnd   = 0;
            segPoints[dim][pos] = tempSegPoints[num];
            for (i = 0; i < ruleset->num; i ++) {
                if (ruleset->ruleList[i].range[dim][0] == tempSegPoints[num]) {
                    /*printf ("\n>>rule[%d] range[0]=%x", i, ruleset->ruleList[i].range[dim][0]);*/
                    /*this segment point is a start point*/
                    ifStart = 1;
                    break;
                }
            }
            for (i = 0; i < ruleset->num; i ++) {
                if (ruleset->ruleList[i].range[dim][1] == tempSegPoints[num]) {
                    /*printf ("\n>>rule[%d] range[1]=%x", i, ruleset->ruleList[i].range[dim][1]);*/
                    /* this segment point is an end point */
                    ifEnd = 1;
                    break;
                }
            }
            if (ifStart && ifEnd) {
                segPointsInfo[dim][pos] = 0;
                pos ++;
                segPoints[dim][pos] = tempSegPoints[num];
                segPointsInfo[dim][pos] = 1;
                pos ++;
            }
            else if (ifStart) {
                segPointsInfo[dim][pos] = 0;
                pos ++;
            }
            else {
                segPointsInfo[dim][pos] = 1;
                pos ++;
            }

        }

        /* now pos is the total number of points in the spanned segment point list */

        if (depth == 0) {
            gNumNonOverlappings[dim] = pos;
            gNumTotalNonOverlappings *= (unsigned long long) pos;
        }

#ifdef  DEBUG
        printf("\n>>dim[%d] segs: ", dim);
        for (num = 0; num < pos; num++) {
            /*if (!(num % 10))  printf("\n");*/
            printf ("%x(%u) ", segPoints[dim][num], segPointsInfo[dim][num]);
        }
#endif /* DEBUG */

        if (pos >= 3) {
            hightAll = 0;
            hightList = (unsigned int *) malloc(pos * sizeof(unsigned int));
            for (i = 0; i < pos-1; i++) {
                hightList[i] = 0;
                for (j = 0; j < ruleset->num; j++) {
                    if (ruleset->ruleList[j].range[dim][0] <= segPoints[dim][i] \
                            && ruleset->ruleList[j].range[dim][1] >= segPoints[dim][i+1]) {
                        hightList[i]++;
                        hightAll++;
                    }
                }
            }
            if (hightAvg > hightAll/(pos-1)) {  /* possible choice for d2s, pos-1 is the number of segs */
                float hightSum = 0;

                /* select current dimension */
                d2s = dim;
                hightAvg = hightAll/(pos-1);

                /* the first segment MUST belong to the leff child */
                hightSum += hightList[0];
                for (num = 1; num < pos-1; num++) {  /* pos-1 >= 2; seg# = num */
                    if (segPointsInfo[d2s][num] == 0)
                        thresh = segPoints[d2s][num] - 1;
                    else
                        thresh = segPoints[d2s][num];

                    if (hightSum > hightAll/2) {
                        break;
                    }
                    hightSum += hightList[num];
                }
                /*printf("\n>>d2s=%u thresh=%x\n", d2s, thresh);*/
                range[0][0] = segPoints[d2s][0];
                range[0][1] = thresh;
                range[1][0] = thresh + 1;
                range[1][1] = segPoints[d2s][pos-1];
            }
            /* print segment list of each dim */
#ifdef  DEBUG
            printf("\n>>hightAvg=%f, hightAll=%f, segs=%d", hightAll/(pos-1), hightAll, pos-1);
            for (num = 0; num < pos-1; num++) {
                printf ("\nseg%5d[%8x, %8x](%u) ",
                        num, segPoints[dim][num], segPoints[dim][num+1], hightList[num]);
            }
#endif /* DEBUG */
            free(hightList);
        } /* pos >=3 */

        if (maxDiffSegPts < pos) {
            maxDiffSegPts = pos;
        }
    }
    free(tempSegPoints);

    /*Update Leaf node*/
    if (maxDiffSegPts <= 2) {
        currNode->d2s = 0;
        currNode->depth = depth;
        currNode->thresh = (unsigned int) ruleset->ruleList[0].pri;
        currNode->child[0] = NULL;
        currNode->child[1] = NULL;

        for (dim = 0; dim < DIM; dim ++) {
            free(segPoints[dim]);
            free(segPointsInfo[dim]);
        }
#ifdef DEBUG
        printf("\n>>LEAF-NODE: matching rule %d", ruleset->ruleList[0].pri);
#endif /* DEBUG */

        gChildCount ++;
        gNumLeafNode ++;
#ifndef LOOKUP
        if (gNumLeafNode % 1000000 == 0)
            printf(".");
#endif
            /*printf("\n>>#%8dM leaf-node generated", gNumLeafNode/1000000);*/
        if (gWstDepth < depth)
            gWstDepth = depth;
        gAvgDepth += depth;
        return  SUCCESS;
    }

    /*Update currNode*/
    /*Binary split along d2s*/

#ifdef DEBUG
    /* split info */
    printf("\n>>d2s=%u; thresh=0x%8x, range0=[%8x, %8x], range1=[%8x, %8x]",
            d2s, thresh, range[0][0], range[0][1], range[1][0], range[1][1]);
#endif /* DEBUG */


    if (range[1][0] > range[1][1]) {
        printf("\n>>maxDiffSegPts=%d  range[1][0]=%x  range[1][1]=%x",
                maxDiffSegPts, range[1][0], range[1][1]);
        printf("\n>>fuck\n"); exit(0);
    }


    for (dim = 0; dim < DIM; dim ++) {
        free(segPoints[dim]);
        free(segPointsInfo[dim]);
    }

    gNumTreeNode ++;
    currNode->d2s = (unsigned char) d2s;
    currNode->depth = (unsigned char) depth;
    currNode->thresh = thresh;
    currNode->child[0] = (hs_node_t *) malloc(sizeof(hs_node_t));

    /*Generate left child rule list*/
    tempRuleNumList = (unsigned int*) malloc(ruleset->num * sizeof(unsigned int)); /* need to be freed */
    pos = 0;
    for (num = 0; num < ruleset->num; num++) {
        if (ruleset->ruleList[num].range[d2s][0] <= range[0][1]
        &&  ruleset->ruleList[num].range[d2s][1] >= range[0][0]) {
            tempRuleNumList[pos] = num;
            pos++;
        }
    }
    childRuleSet = (rule_set_t*) malloc(sizeof(rule_set_t));
    childRuleSet->num = pos;
    childRuleSet->ruleList = (rule_t*) malloc( childRuleSet->num * sizeof(rule_t) );
    for (num = 0; num < childRuleSet->num; num++) {
        childRuleSet->ruleList[num] = ruleset->ruleList[tempRuleNumList[num]];
        /* in d2s dim, the search space needs to be trimmed off */
        if (childRuleSet->ruleList[num].range[d2s][0] < range[0][0])
            childRuleSet->ruleList[num].range[d2s][0] = range[0][0];
        if (childRuleSet->ruleList[num].range[d2s][1] > range[0][1])
            childRuleSet->ruleList[num].range[d2s][1] = range[0][1];
    }
    free(tempRuleNumList);

    BuildHSTree(childRuleSet, currNode->child[0], depth+1);

#ifndef LOOKUP
    free(currNode->child[0]);
#endif
    //Modified by kun, should clear memory no matter LOOKUP or not
    free(childRuleSet->ruleList);
    free(childRuleSet);

    /*Generate right child rule list*/
    currNode->child[1] = (hs_node_t *) malloc(sizeof(hs_node_t));
    tempRuleNumList = (unsigned int*) malloc(ruleset->num * sizeof(unsigned int)); /* need to be free */
    pos = 0;
    for (num = 0; num < ruleset->num; num++) {
        if (ruleset->ruleList[num].range[d2s][0] <= range[1][1]
        &&  ruleset->ruleList[num].range[d2s][1] >= range[1][0]) {
            tempRuleNumList[pos] = num;
            pos++;
        }
    }

    childRuleSet = (rule_set_t*) malloc(sizeof(rule_set_t));
    childRuleSet->num = pos;
    childRuleSet->ruleList = (rule_t*) malloc( childRuleSet->num * sizeof(rule_t) );
    for (num = 0; num < childRuleSet->num; num++) {
        childRuleSet->ruleList[num] = ruleset->ruleList[tempRuleNumList[num]];
        /* in d2s dim, the search space needs to be trimmed off */
        if (childRuleSet->ruleList[num].range[d2s][0] < range[1][0])
            childRuleSet->ruleList[num].range[d2s][0] = range[1][0];
        if (childRuleSet->ruleList[num].range[d2s][1] > range[1][1])
            childRuleSet->ruleList[num].range[d2s][1] = range[1][1];
    }

    free(tempRuleNumList);
    BuildHSTree(childRuleSet, currNode->child[1], depth+1);


#ifndef LOOKUP
    free(currNode->child[1]);
#endif
    //Modified by kun, should clear memory no matter LOOKUP or not
    free(childRuleSet->ruleList);
    free(childRuleSet);

    return  SUCCESS;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  LookupHSTtree
 *  Description:  test the hyper-split-tree with give 4-tuple packet
 * =====================================================================================
 */
int LookupHSTree(rule_set_t* ruleset, hs_node_t* root)
{
    unsigned int    ruleNum;

    /*for (ruleNum = ruleset->num-1; ruleNum < ruleset->num; ruleNum ++) {*/
    for (ruleNum = 0; ruleNum < ruleset->num; ruleNum ++) {
        hs_node_t*  node = root;
        unsigned int    packet[DIM];
        packet[0] = ruleset->ruleList[ruleNum].range[0][0];
        packet[1] = ruleset->ruleList[ruleNum].range[1][0];
        packet[2] = ruleset->ruleList[ruleNum].range[2][0];
        packet[3] = ruleset->ruleList[ruleNum].range[3][0];
        packet[4] = ruleset->ruleList[ruleNum].range[4][0];
        while (node->child[0] != NULL) {
            if (packet[node->d2s] <= node->thresh)
                node = node->child[0];
            else
                node = node->child[1];
        }
        printf("\n>>LOOKUP RESULT");
        printf("\n>>packet:     [%8x %8x], [%8x %8x], [%5u %5u], [%5u %5u], [%2x %2x]",
                packet[0], packet[0],
                packet[1], packet[1],
                packet[2], packet[2],
                packet[3], packet[3],
                packet[4], packet[4]);
        printf("\n>>Expect Rule%d:  [%8x %8x], [%8x %8x], [%5u %5u], [%5u %5u], [%2x %2x]", ruleNum+1,
                ruleset->ruleList[ruleNum].range[0][0], ruleset->ruleList[ruleNum].range[0][1],
                ruleset->ruleList[ruleNum].range[1][0], ruleset->ruleList[ruleNum].range[1][1],
                ruleset->ruleList[ruleNum].range[2][0], ruleset->ruleList[ruleNum].range[2][1],
                ruleset->ruleList[ruleNum].range[3][0], ruleset->ruleList[ruleNum].range[3][1],
                ruleset->ruleList[ruleNum].range[4][0], ruleset->ruleList[ruleNum].range[4][1]);
        printf("\n>>Matched Rule%d: [%8x %8x], [%8x %8x], [%5u %5u], [%5u %5u], [%2x %2x]", node->thresh+1,
                ruleset->ruleList[node->thresh].range[0][0], ruleset->ruleList[node->thresh].range[0][1],
                ruleset->ruleList[node->thresh].range[1][0], ruleset->ruleList[node->thresh].range[1][1],
                ruleset->ruleList[node->thresh].range[2][0], ruleset->ruleList[node->thresh].range[2][1],
                ruleset->ruleList[node->thresh].range[3][0], ruleset->ruleList[node->thresh].range[3][1],
                ruleset->ruleList[node->thresh].range[4][0], ruleset->ruleList[node->thresh].range[4][1]);

    }

    return  SUCCESS;
}
/*
 * ===  FUNCTION  ======================================================================
 *         Name:  main
 *  Description:  yes, this is where we start.
 * =====================================================================================
 */
unsigned int pt[MAX_TRACES][5];

int main(int argc, char* argv[])
{
    rule_set_t      ruleset;
    hs_node_t       rootnode;
//  char            filename[40] = "./acl1";    /* filter file name */

    //Changed by kun
    if (argc < 3) {
        printf("Usage: hs filter_set_file trace_file\n");
        return 1;
    }

    gettimeofday(&gStartTime,NULL);

    /* load rules from file */
    ReadFilterFile(&ruleset, argv[1]);
    /* build hyper-split tree */

#ifndef LOOKUP
    printf("\n\n>>Building HyperSplit tree (%u rules, 5-tuple)", ruleset.num);
#endif

    BuildHSTree(&ruleset, &rootnode, 0);

/*#ifdef  LOOKUP*/
    /*LookupHSTree(&ruleset, &rootnode);*/
/*#endif*/
    gettimeofday(&gEndTime,NULL);

#ifndef LOOKUP
    printf("\n\n>>RESULTS:");
    printf("\n>>number of children:     %d", gChildCount);
    printf("\n>>worst case tree depth:  %d", gWstDepth);
    printf("\n>>average tree depth:     %f", (float) gAvgDepth/gChildCount);
    printf("\n>>number of tree nodes:%d", gNumTreeNode);
    printf("\n>>number of leaf nodes:%d", gNumLeafNode);
    printf("\n>>total memory: %d(KB)", ((gNumTreeNode*8)>>10) + ((gNumLeafNode*4)>>10));
    printf("\n>>preprocessing time: %ld(ms)", 1000*(gEndTime.tv_sec - gStartTime.tv_sec)
            + (gEndTime.tv_usec - gStartTime.tv_usec)/1000);
    printf("\n\n>>SUCCESS in building HyperSplit tree :-)\n\n");
#endif

#ifdef LOOKUP
    //Speed test, added by kun
    fpt = fopen(argv[2], "r");
    struct flow *flows = read_trace_file(fpt);
    int error_cnt = 0;
    long elapsedTimeMicroSec;

    for (int i = 0; i < trace_rule_num; i++) {
        pt[i][0] = flows[i].src_ip;
        pt[i][1] = flows[i].dst_ip;
        pt[i][2] = flows[i].src_port;
        pt[i][3] = flows[i].dst_port;
        pt[i][4] = flows[i].proto;
    }

    hs_node_t*  node;

    gettimeofday(&gStartTime, NULL);
    for (int i = 0; i < trace_rule_num; i++) {
        node = &rootnode;
        while (node->child[0] != NULL) {
            if (pt[i][node->d2s] <= node->thresh){
                node = node->child[0];
            }
            else{
                node = node->child[1];
            }
        }
        if (node->thresh != flows[i].trueRID - 1) {
            error_cnt++;
        }
    }
    gettimeofday(&gEndTime, NULL);

    elapsedTimeMicroSec = (gEndTime.tv_sec - gStartTime.tv_sec) * 1000000;
    elapsedTimeMicroSec += (gEndTime.tv_usec - gStartTime.tv_usec);
    unsigned long long total_memory = gNumTreeNode*8 + gNumLeafNode*4;
    unsigned long long total_memory_in_kb = total_memory / 1024 + (total_memory % 1024 == 0? 0: 1);
    printf("%lldKB\t", total_memory_in_kb);
    printf("%.4lfMqps\n", (double)trace_rule_num / (double)elapsedTimeMicroSec);
#endif
    return SUCCESS;
}
#endif   /* ----- #ifndef _HS_C ----- */
