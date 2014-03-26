library jwt.all_jwt.test;

import 'package:unittest/unittest.dart';
//import 'claim_set_test.dart' as claim_set;
import 'jwt_test.dart' as jwt;
import 'jwa_test.dart' as jwa;

void main() {
//  group('claim_set', claim_set.main);
  group('jwt', jwt.main);
  group('jwa', jwa.main);
}