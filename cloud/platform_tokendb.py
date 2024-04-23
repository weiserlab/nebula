import hashlib
from concurrent.futures import ThreadPoolExecutor
import threading

DEBUG = False
class ConcurrentDict:
    def __init__(self):
        self._dict = {}
        self._dict_lock=threading.Lock()

    def add_if_not_exists(self, key, value):
        with self._dict_lock:
            if key not in self._dict:
                self._dict[key] = value
                return None
            return self._dict[key]

class StringSet:
    def __init__(self, num_shards=32):
        self._shards = [ConcurrentDict() for _ in range(num_shards)]

    def _get_shard(self, key):
        if isinstance(key, str):
            key = key.encode()
        hash_key = hashlib.blake2b(key).hexdigest()
        shard_index = int(hash_key, 16) % len(self._shards)
        return self._shards[shard_index]

    def add_if_not_exists(self, key, value=True):
        shard = self._get_shard(key)
        return shard.add_if_not_exists(key, value)

    def add_new_elements(self, keys, values=None, max_workers=256):
        if values is None:
            values = [True] * len(keys)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(self.add_if_not_exists, keys, values)
        return results

if DEBUG:
    sharded_dict = StringSet()
    keys = ['key1', 'key2', 'key3', 'key4', 'key5']
    results = sharded_dict.add_new_elements(keys)
    print(results)

