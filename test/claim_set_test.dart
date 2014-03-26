library claim_set.test;

import 'package:jwt/jwt.dart';
import 'package:crypto/crypto.dart';

void main()  {
  final JwtClaimSet claimSet = 
      new MutableJwtClaimSet()
        ..issuer='fred';
  //https://addon-user-tester-aholmgren.herokuapp.com/jira/issue-tester?tz=Australia%2FSydney&loc=en-US&user_id=admin&user_key=admin&xdm_e=https%3A%2F%2Fconnect-rc7-jira.jira-dev.com&xdm_c=channel-issue-tester-jira--ah1-rd&cp=&lic=none&jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzOTQxNjYzNjcsInN1YiI6ImFkbWluIiwiaXNzIjoiamlyYTphZTM5MGQyOS0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJxc2giOiJlYjRlYzVmMDk4MGQwMWRhMzA2ZGI4OWZhNTdkZDE2MzU3NDY2NzQzNmRkNzIwZDVkOWM1Mjc5YzViNDVmN2E4IiwiaWF0IjoxMzk0MTY2MTg3fQ.bR8Z0MIguOg6xgHiav0quun8kTqXzNUKMKym-PFjZvc
  
//  String jwtStr = r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzOTQxNjYzNjcsInN1YiI6ImFkbWluIiwiaXNzIjoiamlyYTphZTM5MGQyOS0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJxc2giOiJlYjRlYzVmMDk4MGQwMWRhMzA2ZGI4OWZhNTdkZDE2MzU3NDY2NzQzNmRkNzIwZDVkOWM1Mjc5YzViNDVmN2E4IiwiaWF0IjoxMzk0MTY2MTg3fQ.bR8Z0MIguOg6xgHiav0quun8kTqXzNUKMKym-PFjZvc';
  String jwtStr = r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzOTQxNjYzNjcsInN1YiI6ImFkbWluIiwiaXNzIjoiamlyYTphZTM5MGQyOS0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJxc2giOiJlYjRlYzVmMDk4MGQwMWRhMzA2ZGI4OWZhNTdkZDE2MzU3NDY2NzQzNmRkNzIwZDVkOWM1Mjc5YzViNDVmN2E4IiwiaWF0IjoxMzk0MTY2MTg3fQ==.bR8Z0MIguOg6xgHiav0quun8kTqXzNUKMKym-PFjZvc=';
  
  print(230 % 4);
  print(CryptoUtils.base64StringToBytes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
  print(CryptoUtils.base64StringToBytes('eyJleHAiOjEzOTQxNjYzNjcsInN1YiI6ImFkbWluIiwiaXNzIjoiamlyYTphZTM5MGQyOS0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJxc2giOiJlYjRlYzVmMDk4MGQwMWRhMzA2ZGI4OWZhNTdkZDE2MzU3NDY2NzQzNmRkNzIwZDVkOWM1Mjc5YzViNDVmN2E4IiwiaWF0IjoxMzk0MTY2MTg3fQ=='));
  print(CryptoUtils.base64StringToBytes('bR8Z0MIguOg6xgHiav0quun8kTqXzNUKMKym-PFjZvc='));
  final jwt = new Jwt.decode(jwtStr);
  print(jwt.claimSet);
}