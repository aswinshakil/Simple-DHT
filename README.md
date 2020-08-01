# Simple-DHT
Designed a peer-to-peer distributed hash table based on the Chord protocol, providing ID space partitioning/re-partitioning, node joins, and ring-based routing for insert, delete, and query operations. Done for the course CSE 586: Distributed Systems offered in Spring 2020 at University at Buffalo under the prof. Steve Ko.

## Introduction

Designed and implemented a simple Distributed Hash Table based on Chord protocol. Although the design is based on Chord, it is a simplified version of Chord; did not implement finger tables and finger-based routing; not handle node leaves/failures. Therefore, there are three things we implemented : 
1) ID space partitioning/re-partitioning
2) Ring-based routing
3) Node joins

## Testing
For testing using grader please refer the following doc: 
https://docs.google.com/document/d/1DuT7XLnYheCPzp1vyfGILOrKuxhxPXnAWkIAxCYRtkA/edit

## Reference:
https://cse.buffalo.edu/~stevko/courses/cse486/spring20/lectures/15-dht.pdf
