#!/usr/bin/env python3

"""Tests for linters package."""

# A module that doesn't exist
import foooooooooafdsfdfdsfdsfdsfdfd

# a very long line
print("This is a very long line aaaaaa aaaaa aaaaaa aaaaaaa aaaaaa aaaaaaa aaaaaaa aaaaaaaa aaaaaaa aaaaaaa aaaaaaaa aaaaa")

# an unused variable
unused_variable = 1

# a variable that is used before it is defined
print(used_before_defined)

foo("hello")
bar("hello")
baz("hello")


def foo(hello: str) -> None:
    """A function that doesn't use its argument."""
    return


def bar(hello: str) -> None:
    """A function that returns the wrong type."""
    print(hello)
    return hello


def baz(hello: int) -> None:
    """A function that will be called with the wrong type annotation."""
    print(hello)
    return None
