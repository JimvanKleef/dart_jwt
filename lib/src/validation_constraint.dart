library validation.constraint;

// TODO: this should be moved into a separate validat project

class ConstraintViolation {
  final String message;

  ConstraintViolation(this.message);
  
  @override
  String toString() => message;
}
