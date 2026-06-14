# Test cases for FeatureExtractor.extract()

This README file explains the test cases in the `test.py` module, which tests the correct execution of the `FeatureExtractor.extract()` method.

## Scenarios

The test cases cover various combinations of the following scenarios:

1. Non-duplex conversation
2. Duplex conversation
3. Connection-oriented protocol
4. Connection-less protocol
5. Multi-origin scenario
6. Non-multi-origin scenario
7. Terminating flag set
8. Non-terminating flags set
9. Interleaved connections
10. Non-interleaved connection
11. Exceeding max IAT
12. Non-exceeding max IAT

## Test termination 
* Given in `test_termination.py`


## Test estabilishment
* Given in `test_handshake.py`



## Test Case Descriptions

1. `Test case 1) Non-duplex | connection-oriented | non multi-origin | non-terminating | non exceeding-max iat `: ✅
  - Description: Tests the `extract()` method for a non-duplex conversation using a connection-oriented protocol in a non-multi-origin scenario with non-terminating flags set and non-exceeding max IAT.
  - To run test case add the following to the  `test_extract`: 
  ```python 
  test_cases = [
    self._load_test_case_1()
  ]
  ```
  - View packets and intermediate results in the  `test_case1.xlsx ` file at the current directory.
  
  <br />
  

2. `Test case 2) Non-duplex | connection-oriented | multi-origin | non-terminating | non exceeding-max iat `: ✅

  - Description: Tests the `extract()` method for a non-duplex conversation using a connection-oriented protocol in a multi-origin scenario with non-terminating flags set and non-exceeding max IAT.
  - To run test case add the following to the  `test_extract`: 
  ```python 
  test_cases = [
    self._load_test_case_2()
  ]
  ```
  - View packets and intermediate results in the  `test_case2.xlsx ` file at the current directory


3. `Test case 3) Non-duplex | connection-less | not multi-origin | non-terminating | non exceeding-max iat`:  ✅
  - Description: Tests the `extract()` method for a non-duplex conversation using a connection-less protocol in a non-multi-origin scenario with non-termination flags set and non-exceeding max IAT.
  - To run test case add the following to the  `test_extract`: 
  ```python 
  test_cases = [
    self._load_test_case_3()
  ]
  ```
  - View packets and intermediate results in the  `test_case3.xlsx ` file at the current directory

  4. `Test case 4) Non-duplex | connection-less | multi-origin | non-terminating | exceeding-max iat`:  ✅
  - Description: Tests the `extract()` method for a non-duplex conversation using a connection-less protocol in a non-multi-origin scenario with non-termination flags set and exceeding max IAT.
  - To run test case add the following to the  `test_extract`: 
  ```python 
  test_cases = [
    self._load_test_case_4()
  ]
  ```
  - View packets and intermediate results in the  `test_case4.xlsx ` file at the current directory
  <br />

5. `Test case 5) duplex | connection-oriented | non-multi-origin | terminating | non - exceeding-max iat `: ✅
  - Description: Tests the `extract()` method for a duplex conversation using a connection-oriented protocols to monitor methods in a multi-origin scenario with terminating flags set and non exceeding max IAT.
  - To run test case add the following to the  `test_extract`: 
  ```python 
  test_cases = [
    self._load_test_case_5()
  ]
  ```
  - View packets and intermediate results in the  `test_case5.xlsx ` file at the current directory.
  
  <br />

6. `Test case 6) Duplex | connection-oriented | multi-origin | terminating | non - exceeding-max iat | Intereaved `: ✅
  - Description: Tests the `extract()` method for a duplex conversation using a connection-oriented protocol to monitor methods in a multi-origin scenario with terminating flags set and connectiones interleaved.
  - To run test case add the following to the  `test_extract`: 
  ```python 
  test_cases = [
    self._load_test_case_7()
  ]
  ```
  - View packets and intermediate results in the  `test_case6.xlsx ` file at the current directory.






