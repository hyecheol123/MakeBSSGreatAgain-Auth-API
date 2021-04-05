/**
 * Method to check username rule
 *  - Contains at least one character, only allow small characters and numbers
 *  - At least 6 character long, maximum of 15 character long
 *  - Start with an alphabet
 *
 * @param username username of the user
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */
export default function usernameRule(username: string): boolean {
  const smallLetterRegExp = /[a-z]/;
  const notAllowedRegExp = /[^0-9a-z]/;
  const usernameRegExp = /^(?=.*[a-z])[a-z0-9]{5,15}/;

  // Check whether the username contains not allowed characters
  if (notAllowedRegExp.test(username)) {
    return false;
  }

  // Check rule 1, 2
  if (!usernameRegExp.test(username)) {
    return false;
  }

  // First character needs to be alphabet
  return smallLetterRegExp.test(username.substring(0, 1));
}
