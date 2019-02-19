//
// Created by hx1997 on 2019/2/11.
//

#include "search.h"

int binary_search_lower(Inst insts[], int l, int r, int key) {
    int mid = l + (r - l) / 2;
    // if search scope has been narrowed down to nothing,
    // then either we have found the key, or the key does not exist in the array
    if (l > r) {
        if (insts[mid].opcode == key)
            return mid;
        else
            return -1;
    }

    if (insts[mid].opcode >= key)
        return binary_search_lower(insts, l, mid - 1, key);
    else
        return binary_search_lower(insts, mid + 1, r, key);
}