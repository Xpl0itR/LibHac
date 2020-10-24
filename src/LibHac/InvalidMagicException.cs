using System;
using System.Runtime.Serialization;

namespace LibHac
{
    /// <summary>
    /// This is the exception that is thrown when the actual magic number doesn't not match the expected magic number
    /// </summary>
    [Serializable]
    public class InvalidMagicException : LibHacException, ISerializable
    {
        /// <summary>
        /// The expected magic number
        /// </summary>
        public string ExpectedMagic { get; }

        /// <summary>
        /// The actual magic number
        /// </summary>
        public string ActualMagic { get; }

        /// <summary>
        ///  Initializes a new instance of the <see cref="InvalidMagicException"/> class with a specified error message,
        ///  information about the missing key and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="expectedMagic">The expected magic number.</param>
        /// <param name="actualMagic">The actual magic number.</param>
        public InvalidMagicException(string expectedMagic, string actualMagic)
            : base($"This means the file is encrypted or corrupt. Expected magic: {expectedMagic}. Actual magic: {actualMagic}")
        {
            (ExpectedMagic, ActualMagic) = (expectedMagic, actualMagic);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidMagicException"/> class. 
        /// </summary>
        public InvalidMagicException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidMagicException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        public InvalidMagicException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidMagicException"/> class with serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data about the exception being thrown.</param>
        /// <param name="context">The <see cref="StreamingContext"/>  that contains contextual information about the source or destination.</param>
        protected InvalidMagicException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            (ExpectedMagic, ActualMagic) = (info.GetString(nameof(ExpectedMagic)), info.GetString(nameof(ActualMagic)));
        }

        void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue(nameof(ExpectedMagic), ExpectedMagic);
            info.AddValue(nameof(ActualMagic), ActualMagic);
        }
    }
}
