class Retry:
    def __init__(self, retry_class, retry_limit = 0, retry_funcs=[], *args):
        self.retry_limit = retry_limit
        self.retry_class = retry_class(*args)
        self.retry_funcs = retry_funcs
    def __getattr__(self, name):
        if name in self.retry_funcs:
            retry = 0
            while True:
                try:
                    return self.retry_class.__getattribute__(name)
                except:
                    if retry < self.retry_limit + 1:
                        retry = retry + 1
                    else:
                        raise
        return self.retry_class.__getattribute__(name)


