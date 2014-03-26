library validation.constraint;

// TODO: this should be moved into a separate validat project

class ConstraintViolation {
  final String message;

  ConstraintViolation(this.message);
  
  @override
  String toString() => message;
}


class ConstraintViolations {
  final Set<ConstraintViolation> violations;
  
  // TODO: likely too simplistic
  String get summaryMessage => violations.join('\n');
  
  ConstraintViolations(this.violations);
}