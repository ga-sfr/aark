export function validBitLockerRecoveryPassword(value: string): boolean {
  const groups = value.split("-");
  if (groups.length !== 8 || groups.some((group) => !/^\d{6}$/.test(group))) return false;
  return groups.every((group) => {
    const number = Number(group);
    return number <= 720_885 && number % 11 === 0;
  });
}
