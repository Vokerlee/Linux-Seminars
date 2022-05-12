#include "list.h"
#include <stdlib.h>
#include <stdio.h>

struct kek_struct_
{
    char stuff[BUFSIZ];
    list_head list;
};

typedef struct kek_struct_ kek_struct;

LIST_HEAD(global_list);

int main()
{
    kek_struct k1 = {.stuff = "1234567890qwertyuiop"};
    kek_struct k2 = {.stuff = "ghhghghghghghghghghg"};
    INIT_LIST_HEAD(&k1.list);
    INIT_LIST_HEAD(&k2.list);

    kek_struct *kek_iterator  = NULL;
    list_head  *list_iterator = NULL;

    list_add(&global_list, &k1.list);
    list_add_tail(&global_list, &k2.list);

    list_foreach(list_iterator, &global_list)
    {
        printf("%s\n", container_of(list_iterator, struct kek_struct_, list)->stuff);
    }

    list_foreach_entry(kek_iterator, &global_list, list)
    {
        printf("%s\n", kek_iterator->stuff);
    }


    

}