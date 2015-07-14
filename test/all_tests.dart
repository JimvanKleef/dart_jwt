library jwt.all_jwt.test;

import 'package:test/test.dart';
import 'jwt_test.dart' as jwt;
import 'jwa_test.dart' as jwa;

void main() {
  group('jwt', jwt.main);
  group('jwa', jwa.main);
}
