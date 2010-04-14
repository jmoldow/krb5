/*
 * plugin_default_manager.h
 *
 */

#ifndef PLUGIN_DEFAULT_MANAGER_H_
#define PLUGIN_DEFAULT_MANAGER_H_

#include <plugin_manager.h>

typedef struct {
    char api_name[512];
    plhandle* first;
    plhandle* last;
    int size;
} reg_entry;

typedef struct {
    reg_entry* table;
    long registry_size;
    long registry_max_size;
} registry_data;

typedef struct {
    registry_data* registry;
} manager_data;

plugin_manager* plugin_default_manager_get_instance(void);

#endif /* PLUGIN_DEFAULT_MANAGER_H_ */