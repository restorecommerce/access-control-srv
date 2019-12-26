export class InvalidRequest extends Error {
  constructor(missingParameter: string) {
    super();
    this.message = `Missing ${missingParameter} in Request`;
  }
}

export class InvalidRequestContext extends Error {
  constructor(reason: string) {
    super();
    this.message = `Invalid request context: ${reason}`;
  }
}

export class InvalidCombiningAlgorithm extends Error {
  constructor(combiningAlgorithm: string) {
    super();
    this.message = `Invalid combining algorithm: ${combiningAlgorithm}`;
  }
}

export class UnsupportedResourceAdapter extends Error {
  constructor(config: any) {
    super();
    this.message = `Unsupported resource adapter config ${JSON.stringify(config)}`;
  }
}

export class UnexpectedContextQueryResponse extends Error {
  constructor(response?: any) {
    super();
    this.message = `Unexpected context query response ${response}`;
  }
}
