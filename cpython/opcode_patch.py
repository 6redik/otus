#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""

"""

import dis

def fib(n): return fib(n - 1) + fib(n - 2) if n > 1 else n


if __name__ == "__main__":

    print(dis.dis(fib))
