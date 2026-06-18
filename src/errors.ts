import { JSONRPCErrorException } from "json-rpc-2.0";

// -1xx: state / uniqueness errors

export class CannotChange extends JSONRPCErrorException {
  constructor(fields: string[] = [], data?: object) {
    super("Cannot change", -100, data ?? { fields });
  }
}

export class InvoiceNotReserved extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Invoice not reserved", -101, data);
  }
}

export class TransferIdInUse extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Transfer ID in use", -102, data);
  }
}

export class OperationNotFound extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Operation not found", -104, data);
  }
}

export class OperationExpired extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Operation expired", -105, data);
  }
}

export class AlreadyAcked extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Already acked", -107, data);
  }
}

export class FileTooLarge extends JSONRPCErrorException {
  constructor(data?: object) {
    super("File too large", -108, data);
  }
}

export class TooManyTransfers extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Too many transfers", -109, data);
  }
}

export class SignedTxTooLarge extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Signed TX too large", -110, data);
  }
}

export class InvoiceExpired extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Invoice expired", -111, data);
  }
}

export class InvoiceQuotaExceeded extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Invoice quota exceeded", -112, data);
  }
}

export class TransferIdDeleted extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Transfer ID deleted", -113, data);
  }
}

// Reports the difficulty currently required, so the sender can retry
export class InvalidProofOfWork extends JSONRPCErrorException {
  constructor(powDifficulty: number, data?: object) {
    super(
      "Invalid proof of work",
      -114,
      data ?? { pow_difficulty: String(powDifficulty) },
    );
  }
}

// -2xx: invalid parameter errors

export class Invalid extends JSONRPCErrorException {
  constructor(fields: string[], data?: object) {
    super("Invalid", -200, data ?? { fields });
  }
}

// -3xx: missing parameter errors

export class Missing extends JSONRPCErrorException {
  constructor(fields: string[], data?: object) {
    super("Missing", -300, data ?? { fields });
  }
}

export class MissingFile extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Missing file", -301, data);
  }
}

// -4xx: not-found errors

export class NotFoundConsignment extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Consignment not found", -400, data);
  }
}

export class NotFoundMedia extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Media not found", -401, data);
  }
}

export class TransferNotFound extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Transfer not found", -402, data);
  }
}

export class TransferDataRetrieved extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Transfer data retrieved", -403, data);
  }
}

// -5xx: security errors

export class InvalidProxyAuthSignature extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Invalid proxy auth signature", -501, data);
  }
}

export class InvalidEndpointAuthSignature extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Invalid endpoint auth signature", -502, data);
  }
}

export class InvalidContentSignature extends JSONRPCErrorException {
  constructor(data?: object) {
    super("Invalid content signature", -503, data);
  }
}
