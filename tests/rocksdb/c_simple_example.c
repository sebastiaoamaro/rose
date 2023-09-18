//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "rocksdb/c.h"

#if defined(OS_WIN)
#include <Windows.h>
#else
#include <unistd.h>  // sysconf() - get CPU count
#endif

#if defined(OS_WIN)
const char DBPath[] = "C:\\Windows\\TEMP\\rocksdb_c_simple_example";
const char DBBackupPath[] =
    "C:\\Windows\\TEMP\\rocksdb_c_simple_example_backup";
#else
const char DBPath[] = "/tmp/rocksdb_c_simple_example";
const char DBBackupPath[] = "/tmp/rocksdb_c_simple_example_backup";
#endif

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

int temporary_auxiliary_function(int iteration){
  int calculation = iteration*10 +5;

  return calculation;
}
int main(int argc, char **argv) {

  int workload_size = strtol(argv[1],NULL,10);
  int call_interval = strtol(argv[2],NULL,10);
  printf("Workload size is %d and call interval is %d\n",workload_size,call_interval);
  rocksdb_t *db;
  rocksdb_backup_engine_t *be;
  rocksdb_options_t *options = rocksdb_options_create();
  // Optimize RocksDB. This is the easiest way to
  // get RocksDB to perform well.
#if defined(OS_WIN)
  SYSTEM_INFO system_info;
  GetSystemInfo(&system_info);
  long cpus = system_info.dwNumberOfProcessors;
#else
  long cpus = sysconf(_SC_NPROCESSORS_ONLN);
#endif
  // Set # of online cores
  rocksdb_options_increase_parallelism(options, (int)(cpus));
  rocksdb_options_optimize_level_style_compaction(options, 0);
  // create the DB if it's not already present
  rocksdb_options_set_create_if_missing(options, 1);

  // open DB
  char *err = NULL;
  db = rocksdb_open(options, DBPath, &err);
  assert(!err);

  // open Backup Engine that we will use for backing up our database
  be = rocksdb_backup_engine_open(options, DBBackupPath, &err);
  assert(!err);


  rocksdb_writeoptions_t *writeoptions = rocksdb_writeoptions_create();

  rocksdb_readoptions_t *readoptions = rocksdb_readoptions_create();

  printf("PID is %d \n",getpid());
  for(int i = 0; i< workload_size;i++){
        // Put key-value
      const char key[] = "key";
      const char *value = "value";
      rocksdb_put(db, writeoptions, key, strlen(key), value, strlen(value) + 1,
                  &err);
      assert(!err);
      // Get value
      size_t len;
      char *returned_value =
          rocksdb_get(db, readoptions, key, strlen(key), &len, &err);
      assert(!err);
      assert(strcmp(returned_value, "value") == 0);
      free(returned_value);
      
      int result = ((i%call_interval)==0);

      if (result){
        int storing = temporary_auxiliary_function(i);
      }
  }

  // create new backup in a directory specified by DBBackupPath
  rocksdb_backup_engine_create_new_backup(be, db, &err);
  assert(!err);

  rocksdb_close(db);

  // If something is wrong, you might want to restore data from last backup
  rocksdb_restore_options_t *restore_options = rocksdb_restore_options_create();
  rocksdb_backup_engine_restore_db_from_latest_backup(be, DBPath, DBPath,
                                                      restore_options, &err);
  assert(!err);
  rocksdb_restore_options_destroy(restore_options);

  db = rocksdb_open(options, DBPath, &err);
  assert(!err);

  // cleanup
  rocksdb_writeoptions_destroy(writeoptions);
  rocksdb_readoptions_destroy(readoptions);
  rocksdb_options_destroy(options);
  rocksdb_backup_engine_close(be);
  rocksdb_close(db);

  return 0;
}
